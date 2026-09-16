rule TTP_XOR_QUAD_CurrentVersionRun_0324 {
  strings:
    $key_0324 = { 50 4b [2] 74 45 [2] 5f 69 [2] 71 4b [2] 65 50 [2] 6a 4a [2] 74 57 [2] 76 56 [2] 6d 50 [2] 71 57 [2] 6d 78 }

  condition:
    any of them
}