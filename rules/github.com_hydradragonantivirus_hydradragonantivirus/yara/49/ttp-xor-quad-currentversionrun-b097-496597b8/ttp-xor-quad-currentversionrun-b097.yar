rule TTP_XOR_QUAD_CurrentVersionRun_b097 {
  strings:
    $key_b097 = { e3 f8 [2] c7 f6 [2] ec da [2] c2 f8 [2] d6 e3 [2] d9 f9 [2] c7 e4 [2] c5 e5 [2] de e3 [2] c2 e4 [2] de cb }

  condition:
    any of them
}