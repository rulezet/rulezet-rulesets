rule TTP_XOR_QUAD_CurrentVersionRun_9ad9 {
  strings:
    $key_9ad9 = { c9 b6 [2] ed b8 [2] c6 94 [2] e8 b6 [2] fc ad [2] f3 b7 [2] ed aa [2] ef ab [2] f4 ad [2] e8 aa [2] f4 85 }

  condition:
    any of them
}