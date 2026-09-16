rule TTP_XOR_QUAD_CurrentVersionRun_2aae {
  strings:
    $key_2aae = { 79 c1 [2] 5d cf [2] 76 e3 [2] 58 c1 [2] 4c da [2] 43 c0 [2] 5d dd [2] 5f dc [2] 44 da [2] 58 dd [2] 44 f2 }

  condition:
    any of them
}