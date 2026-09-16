rule TTP_XOR_QUAD_CurrentVersionRun_d7bc {
  strings:
    $key_d7bc = { 84 d3 [2] a0 dd [2] 8b f1 [2] a5 d3 [2] b1 c8 [2] be d2 [2] a0 cf [2] a2 ce [2] b9 c8 [2] a5 cf [2] b9 e0 }

  condition:
    any of them
}