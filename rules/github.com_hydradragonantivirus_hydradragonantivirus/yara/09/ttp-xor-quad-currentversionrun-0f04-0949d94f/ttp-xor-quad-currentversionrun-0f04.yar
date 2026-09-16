rule TTP_XOR_QUAD_CurrentVersionRun_0f04 {
  strings:
    $key_0f04 = { 5c 6b [2] 78 65 [2] 53 49 [2] 7d 6b [2] 69 70 [2] 66 6a [2] 78 77 [2] 7a 76 [2] 61 70 [2] 7d 77 [2] 61 58 }

  condition:
    any of them
}