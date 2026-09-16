rule TTP_XOR_QUAD_CurrentVersionRun_045f {
  strings:
    $key_045f = { 57 30 [2] 73 3e [2] 58 12 [2] 76 30 [2] 62 2b [2] 6d 31 [2] 73 2c [2] 71 2d [2] 6a 2b [2] 76 2c [2] 6a 03 }

  condition:
    any of them
}