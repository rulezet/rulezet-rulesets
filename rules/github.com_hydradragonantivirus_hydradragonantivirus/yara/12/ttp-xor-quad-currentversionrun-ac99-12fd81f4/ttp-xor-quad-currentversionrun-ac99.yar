rule TTP_XOR_QUAD_CurrentVersionRun_ac99 {
  strings:
    $key_ac99 = { ff f6 [2] db f8 [2] f0 d4 [2] de f6 [2] ca ed [2] c5 f7 [2] db ea [2] d9 eb [2] c2 ed [2] de ea [2] c2 c5 }

  condition:
    any of them
}