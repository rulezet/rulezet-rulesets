rule TTP_XOR_QUAD_CurrentVersionRun_4aae {
  strings:
    $key_4aae = { 19 c1 [2] 3d cf [2] 16 e3 [2] 38 c1 [2] 2c da [2] 23 c0 [2] 3d dd [2] 3f dc [2] 24 da [2] 38 dd [2] 24 f2 }

  condition:
    any of them
}