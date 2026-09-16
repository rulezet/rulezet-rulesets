rule TTP_XOR_QUAD_CurrentVersionRun_0419 {
  strings:
    $key_0419 = { 57 76 [2] 73 78 [2] 58 54 [2] 76 76 [2] 62 6d [2] 6d 77 [2] 73 6a [2] 71 6b [2] 6a 6d [2] 76 6a [2] 6a 45 }

  condition:
    any of them
}