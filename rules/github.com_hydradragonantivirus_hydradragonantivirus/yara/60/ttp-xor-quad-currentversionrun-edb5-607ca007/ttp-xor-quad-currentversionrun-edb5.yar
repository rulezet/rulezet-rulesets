rule TTP_XOR_QUAD_CurrentVersionRun_edb5 {
  strings:
    $key_edb5 = { be da [2] 9a d4 [2] b1 f8 [2] 9f da [2] 8b c1 [2] 84 db [2] 9a c6 [2] 98 c7 [2] 83 c1 [2] 9f c6 [2] 83 e9 }

  condition:
    any of them
}