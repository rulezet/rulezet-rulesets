rule TTP_XOR_QUAD_CurrentVersionRun_d8ae {
  strings:
    $key_d8ae = { 8b c1 [2] af cf [2] 84 e3 [2] aa c1 [2] be da [2] b1 c0 [2] af dd [2] ad dc [2] b6 da [2] aa dd [2] b6 f2 }

  condition:
    any of them
}