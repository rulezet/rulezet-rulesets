rule TTP_XOR_QUAD_CurrentVersionRun_9ac2 {
  strings:
    $key_9ac2 = { c9 ad [2] ed a3 [2] c6 8f [2] e8 ad [2] fc b6 [2] f3 ac [2] ed b1 [2] ef b0 [2] f4 b6 [2] e8 b1 [2] f4 9e }

  condition:
    any of them
}