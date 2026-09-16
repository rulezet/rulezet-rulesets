rule TTP_XOR_QUAD_CurrentVersionRun_3abc {
  strings:
    $key_3abc = { 69 d3 [2] 4d dd [2] 66 f1 [2] 48 d3 [2] 5c c8 [2] 53 d2 [2] 4d cf [2] 4f ce [2] 54 c8 [2] 48 cf [2] 54 e0 }

  condition:
    any of them
}