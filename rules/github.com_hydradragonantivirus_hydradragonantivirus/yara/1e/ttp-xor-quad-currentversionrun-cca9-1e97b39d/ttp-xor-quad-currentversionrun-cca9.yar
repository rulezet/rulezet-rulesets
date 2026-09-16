rule TTP_XOR_QUAD_CurrentVersionRun_cca9 {
  strings:
    $key_cca9 = { 9f c6 [2] bb c8 [2] 90 e4 [2] be c6 [2] aa dd [2] a5 c7 [2] bb da [2] b9 db [2] a2 dd [2] be da [2] a2 f5 }

  condition:
    any of them
}