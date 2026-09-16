rule TTP_XOR_QUAD_CurrentVersionRun_d097 {
  strings:
    $key_d097 = { 83 f8 [2] a7 f6 [2] 8c da [2] a2 f8 [2] b6 e3 [2] b9 f9 [2] a7 e4 [2] a5 e5 [2] be e3 [2] a2 e4 [2] be cb }

  condition:
    any of them
}