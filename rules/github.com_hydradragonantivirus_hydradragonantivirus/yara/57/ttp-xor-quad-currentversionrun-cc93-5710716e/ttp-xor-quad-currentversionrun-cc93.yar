rule TTP_XOR_QUAD_CurrentVersionRun_cc93 {
  strings:
    $key_cc93 = { 9f fc [2] bb f2 [2] 90 de [2] be fc [2] aa e7 [2] a5 fd [2] bb e0 [2] b9 e1 [2] a2 e7 [2] be e0 [2] a2 cf }

  condition:
    any of them
}