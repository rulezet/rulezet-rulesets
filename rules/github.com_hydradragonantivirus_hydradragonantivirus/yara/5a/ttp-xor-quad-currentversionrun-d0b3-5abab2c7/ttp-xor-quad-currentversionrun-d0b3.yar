rule TTP_XOR_QUAD_CurrentVersionRun_d0b3 {
  strings:
    $key_d0b3 = { 83 dc [2] a7 d2 [2] 8c fe [2] a2 dc [2] b6 c7 [2] b9 dd [2] a7 c0 [2] a5 c1 [2] be c7 [2] a2 c0 [2] be ef }

  condition:
    any of them
}