rule TTP_XOR_QUAD_CurrentVersionRun_044f {
  strings:
    $key_044f = { 57 20 [2] 73 2e [2] 58 02 [2] 76 20 [2] 62 3b [2] 6d 21 [2] 73 3c [2] 71 3d [2] 6a 3b [2] 76 3c [2] 6a 13 }

  condition:
    any of them
}