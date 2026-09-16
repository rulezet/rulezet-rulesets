rule TTP_XOR_QUAD_CurrentVersionRun_9ac4 {
  strings:
    $key_9ac4 = { c9 ab [2] ed a5 [2] c6 89 [2] e8 ab [2] fc b0 [2] f3 aa [2] ed b7 [2] ef b6 [2] f4 b0 [2] e8 b7 [2] f4 98 }

  condition:
    any of them
}