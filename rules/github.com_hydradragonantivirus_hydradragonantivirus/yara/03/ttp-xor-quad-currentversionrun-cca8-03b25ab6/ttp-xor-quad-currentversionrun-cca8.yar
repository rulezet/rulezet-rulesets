rule TTP_XOR_QUAD_CurrentVersionRun_cca8 {
  strings:
    $key_cca8 = { 9f c7 [2] bb c9 [2] 90 e5 [2] be c7 [2] aa dc [2] a5 c6 [2] bb db [2] b9 da [2] a2 dc [2] be db [2] a2 f4 }

  condition:
    any of them
}