rule TTP_XOR_QUAD_CurrentVersionRun_b9c1 {
  strings:
    $key_b9c1 = { ea ae [2] ce a0 [2] e5 8c [2] cb ae [2] df b5 [2] d0 af [2] ce b2 [2] cc b3 [2] d7 b5 [2] cb b2 [2] d7 9d }

  condition:
    any of them
}