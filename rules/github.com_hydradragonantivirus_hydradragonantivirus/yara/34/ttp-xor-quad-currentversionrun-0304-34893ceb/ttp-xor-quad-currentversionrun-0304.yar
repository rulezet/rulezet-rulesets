rule TTP_XOR_QUAD_CurrentVersionRun_0304 {
  strings:
    $key_0304 = { 50 6b [2] 74 65 [2] 5f 49 [2] 71 6b [2] 65 70 [2] 6a 6a [2] 74 77 [2] 76 76 [2] 6d 70 [2] 71 77 [2] 6d 58 }

  condition:
    any of them
}