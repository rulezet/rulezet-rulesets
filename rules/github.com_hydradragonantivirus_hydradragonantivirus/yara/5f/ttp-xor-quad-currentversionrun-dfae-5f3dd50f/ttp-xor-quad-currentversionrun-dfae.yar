rule TTP_XOR_QUAD_CurrentVersionRun_dfae {
  strings:
    $key_dfae = { 8c c1 [2] a8 cf [2] 83 e3 [2] ad c1 [2] b9 da [2] b6 c0 [2] a8 dd [2] aa dc [2] b1 da [2] ad dd [2] b1 f2 }

  condition:
    any of them
}