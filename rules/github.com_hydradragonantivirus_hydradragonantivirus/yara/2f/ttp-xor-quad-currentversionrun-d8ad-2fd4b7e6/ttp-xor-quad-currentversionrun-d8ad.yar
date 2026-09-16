rule TTP_XOR_QUAD_CurrentVersionRun_d8ad {
  strings:
    $key_d8ad = { 8b c2 [2] af cc [2] 84 e0 [2] aa c2 [2] be d9 [2] b1 c3 [2] af de [2] ad df [2] b6 d9 [2] aa de [2] b6 f1 }

  condition:
    any of them
}