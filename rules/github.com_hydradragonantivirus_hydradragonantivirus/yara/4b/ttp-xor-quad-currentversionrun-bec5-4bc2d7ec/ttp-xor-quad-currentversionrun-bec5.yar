rule TTP_XOR_QUAD_CurrentVersionRun_bec5 {
  strings:
    $key_bec5 = { ed aa [2] c9 a4 [2] e2 88 [2] cc aa [2] d8 b1 [2] d7 ab [2] c9 b6 [2] cb b7 [2] d0 b1 [2] cc b6 [2] d0 99 }

  condition:
    any of them
}