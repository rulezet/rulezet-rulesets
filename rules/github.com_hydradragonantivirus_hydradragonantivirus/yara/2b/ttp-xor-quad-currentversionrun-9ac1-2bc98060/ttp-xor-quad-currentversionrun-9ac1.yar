rule TTP_XOR_QUAD_CurrentVersionRun_9ac1 {
  strings:
    $key_9ac1 = { c9 ae [2] ed a0 [2] c6 8c [2] e8 ae [2] fc b5 [2] f3 af [2] ed b2 [2] ef b3 [2] f4 b5 [2] e8 b2 [2] f4 9d }

  condition:
    any of them
}