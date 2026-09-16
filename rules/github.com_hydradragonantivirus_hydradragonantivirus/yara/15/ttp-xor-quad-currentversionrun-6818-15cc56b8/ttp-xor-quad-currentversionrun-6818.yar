rule TTP_XOR_QUAD_CurrentVersionRun_6818 {
  strings:
    $key_6818 = { 3b 77 [2] 1f 79 [2] 34 55 [2] 1a 77 [2] 0e 6c [2] 01 76 [2] 1f 6b [2] 1d 6a [2] 06 6c [2] 1a 6b [2] 06 44 }

  condition:
    any of them
}