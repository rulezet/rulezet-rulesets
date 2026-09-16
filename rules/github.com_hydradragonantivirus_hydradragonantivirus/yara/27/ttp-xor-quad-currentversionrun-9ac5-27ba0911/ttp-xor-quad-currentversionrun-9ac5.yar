rule TTP_XOR_QUAD_CurrentVersionRun_9ac5 {
  strings:
    $key_9ac5 = { c9 aa [2] ed a4 [2] c6 88 [2] e8 aa [2] fc b1 [2] f3 ab [2] ed b6 [2] ef b7 [2] f4 b1 [2] e8 b6 [2] f4 99 }

  condition:
    any of them
}