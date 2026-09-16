rule TTP_XOR_QUAD_CurrentVersionRun_034f {
  strings:
    $key_034f = { 50 20 [2] 74 2e [2] 5f 02 [2] 71 20 [2] 65 3b [2] 6a 21 [2] 74 3c [2] 76 3d [2] 6d 3b [2] 71 3c [2] 6d 13 }

  condition:
    any of them
}