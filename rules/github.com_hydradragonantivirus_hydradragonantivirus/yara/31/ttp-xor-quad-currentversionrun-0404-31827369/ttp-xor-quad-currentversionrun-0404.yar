rule TTP_XOR_QUAD_CurrentVersionRun_0404 {
  strings:
    $key_0404 = { 57 6b [2] 73 65 [2] 58 49 [2] 76 6b [2] 62 70 [2] 6d 6a [2] 73 77 [2] 71 76 [2] 6a 70 [2] 76 77 [2] 6a 58 }

  condition:
    any of them
}