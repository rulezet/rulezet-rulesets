rule TTP_XOR_QUAD_CurrentVersionRun_275f {
  strings:
    $key_275f = { 74 30 [2] 50 3e [2] 7b 12 [2] 55 30 [2] 41 2b [2] 4e 31 [2] 50 2c [2] 52 2d [2] 49 2b [2] 55 2c [2] 49 03 }

  condition:
    any of them
}