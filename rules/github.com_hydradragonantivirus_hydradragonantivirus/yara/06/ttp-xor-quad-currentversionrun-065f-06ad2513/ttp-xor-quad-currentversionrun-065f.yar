rule TTP_XOR_QUAD_CurrentVersionRun_065f {
  strings:
    $key_065f = { 55 30 [2] 71 3e [2] 5a 12 [2] 74 30 [2] 60 2b [2] 6f 31 [2] 71 2c [2] 73 2d [2] 68 2b [2] 74 2c [2] 68 03 }

  condition:
    any of them
}