rule TTP_XOR_QUAD_CurrentVersionRun_0f17 {
  strings:
    $key_0f17 = { 5c 78 [2] 78 76 [2] 53 5a [2] 7d 78 [2] 69 63 [2] 66 79 [2] 78 64 [2] 7a 65 [2] 61 63 [2] 7d 64 [2] 61 4b }

  condition:
    any of them
}