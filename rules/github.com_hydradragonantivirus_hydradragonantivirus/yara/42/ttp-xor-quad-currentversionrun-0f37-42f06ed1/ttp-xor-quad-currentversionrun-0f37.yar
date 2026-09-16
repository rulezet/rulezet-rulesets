rule TTP_XOR_QUAD_CurrentVersionRun_0f37 {
  strings:
    $key_0f37 = { 5c 58 [2] 78 56 [2] 53 7a [2] 7d 58 [2] 69 43 [2] 66 59 [2] 78 44 [2] 7a 45 [2] 61 43 [2] 7d 44 [2] 61 6b }

  condition:
    any of them
}