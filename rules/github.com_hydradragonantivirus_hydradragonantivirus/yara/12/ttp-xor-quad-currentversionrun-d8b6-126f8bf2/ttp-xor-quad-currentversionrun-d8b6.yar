rule TTP_XOR_QUAD_CurrentVersionRun_d8b6 {
  strings:
    $key_d8b6 = { 8b d9 [2] af d7 [2] 84 fb [2] aa d9 [2] be c2 [2] b1 d8 [2] af c5 [2] ad c4 [2] b6 c2 [2] aa c5 [2] b6 ea }

  condition:
    any of them
}