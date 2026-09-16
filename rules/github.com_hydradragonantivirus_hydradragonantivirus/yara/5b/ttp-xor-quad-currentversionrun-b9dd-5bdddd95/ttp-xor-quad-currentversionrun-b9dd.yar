rule TTP_XOR_QUAD_CurrentVersionRun_b9dd {
  strings:
    $key_b9dd = { ea b2 [2] ce bc [2] e5 90 [2] cb b2 [2] df a9 [2] d0 b3 [2] ce ae [2] cc af [2] d7 a9 [2] cb ae [2] d7 81 }

  condition:
    any of them
}