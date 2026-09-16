rule TTP_XOR_QUAD_CurrentVersionRun_0604 {
  strings:
    $key_0604 = { 55 6b [2] 71 65 [2] 5a 49 [2] 74 6b [2] 60 70 [2] 6f 6a [2] 71 77 [2] 73 76 [2] 68 70 [2] 74 77 [2] 68 58 }

  condition:
    any of them
}