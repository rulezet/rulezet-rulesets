rule TTP_XOR_QUAD_CurrentVersionRun_575f {
  strings:
    $key_575f = { 04 30 [2] 20 3e [2] 0b 12 [2] 25 30 [2] 31 2b [2] 3e 31 [2] 20 2c [2] 22 2d [2] 39 2b [2] 25 2c [2] 39 03 }

  condition:
    any of them
}