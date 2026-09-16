rule TTP_XOR_QUAD_CurrentVersionRun_cc97 {
  strings:
    $key_cc97 = { 9f f8 [2] bb f6 [2] 90 da [2] be f8 [2] aa e3 [2] a5 f9 [2] bb e4 [2] b9 e5 [2] a2 e3 [2] be e4 [2] a2 cb }

  condition:
    any of them
}