rule TTP_XOR_QUAD_CurrentVersionRun_525f {
  strings:
    $key_525f = { 01 30 [2] 25 3e [2] 0e 12 [2] 20 30 [2] 34 2b [2] 3b 31 [2] 25 2c [2] 27 2d [2] 3c 2b [2] 20 2c [2] 3c 03 }

  condition:
    any of them
}