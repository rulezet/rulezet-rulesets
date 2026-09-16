rule TTP_XOR_QUAD_CurrentVersionRun_1f19 {
  strings:
    $key_1f19 = { 4c 76 [2] 68 78 [2] 43 54 [2] 6d 76 [2] 79 6d [2] 76 77 [2] 68 6a [2] 6a 6b [2] 71 6d [2] 6d 6a [2] 71 45 }

  condition:
    any of them
}