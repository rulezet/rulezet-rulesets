rule TTP_XOR_QUAD_CurrentVersionRun_225f {
  strings:
    $key_225f = { 71 30 [2] 55 3e [2] 7e 12 [2] 50 30 [2] 44 2b [2] 4b 31 [2] 55 2c [2] 57 2d [2] 4c 2b [2] 50 2c [2] 4c 03 }

  condition:
    any of them
}