rule TTP_XOR_QUAD_CurrentVersionRun_4abc {
  strings:
    $key_4abc = { 19 d3 [2] 3d dd [2] 16 f1 [2] 38 d3 [2] 2c c8 [2] 23 d2 [2] 3d cf [2] 3f ce [2] 24 c8 [2] 38 cf [2] 24 e0 }

  condition:
    any of them
}