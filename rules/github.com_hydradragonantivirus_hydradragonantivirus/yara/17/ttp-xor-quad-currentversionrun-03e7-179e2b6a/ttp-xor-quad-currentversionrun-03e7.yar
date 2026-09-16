rule TTP_XOR_QUAD_CurrentVersionRun_03e7 {
  strings:
    $key_03e7 = { 50 88 [2] 74 86 [2] 5f aa [2] 71 88 [2] 65 93 [2] 6a 89 [2] 74 94 [2] 76 95 [2] 6d 93 [2] 71 94 [2] 6d bb }

  condition:
    any of them
}