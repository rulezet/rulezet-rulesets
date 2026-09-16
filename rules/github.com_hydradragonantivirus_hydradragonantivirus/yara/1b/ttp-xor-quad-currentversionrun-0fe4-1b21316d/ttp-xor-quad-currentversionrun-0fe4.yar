rule TTP_XOR_QUAD_CurrentVersionRun_0fe4 {
  strings:
    $key_0fe4 = { 5c 8b [2] 78 85 [2] 53 a9 [2] 7d 8b [2] 69 90 [2] 66 8a [2] 78 97 [2] 7a 96 [2] 61 90 [2] 7d 97 [2] 61 b8 }

  condition:
    any of them
}