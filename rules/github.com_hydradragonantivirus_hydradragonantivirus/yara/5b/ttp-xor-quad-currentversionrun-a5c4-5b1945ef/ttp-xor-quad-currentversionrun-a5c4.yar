rule TTP_XOR_QUAD_CurrentVersionRun_a5c4 {
  strings:
    $key_a5c4 = { f6 ab [2] d2 a5 [2] f9 89 [2] d7 ab [2] c3 b0 [2] cc aa [2] d2 b7 [2] d0 b6 [2] cb b0 [2] d7 b7 [2] cb 98 }

  condition:
    any of them
}