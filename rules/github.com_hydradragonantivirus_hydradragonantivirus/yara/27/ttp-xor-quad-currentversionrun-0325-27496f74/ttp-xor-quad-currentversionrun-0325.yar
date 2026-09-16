rule TTP_XOR_QUAD_CurrentVersionRun_0325 {
  strings:
    $key_0325 = { 50 4a [2] 74 44 [2] 5f 68 [2] 71 4a [2] 65 51 [2] 6a 4b [2] 74 56 [2] 76 57 [2] 6d 51 [2] 71 56 [2] 6d 79 }

  condition:
    any of them
}