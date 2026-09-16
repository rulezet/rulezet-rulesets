rule TTP_XOR_QUAD_CurrentVersionRun_3615 {
  strings:
    $key_3615 = { 65 7a [2] 41 74 [2] 6a 58 [2] 44 7a [2] 50 61 [2] 5f 7b [2] 41 66 [2] 43 67 [2] 58 61 [2] 44 66 [2] 58 49 }

  condition:
    any of them
}