rule TTP_XOR_QUAD_CurrentVersionRun_b9c5 {
  strings:
    $key_b9c5 = { ea aa [2] ce a4 [2] e5 88 [2] cb aa [2] df b1 [2] d0 ab [2] ce b6 [2] cc b7 [2] d7 b1 [2] cb b6 [2] d7 99 }

  condition:
    any of them
}