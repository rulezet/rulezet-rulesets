rule TTP_XOR_QUAD_CurrentVersionRun_5aae {
  strings:
    $key_5aae = { 09 c1 [2] 2d cf [2] 06 e3 [2] 28 c1 [2] 3c da [2] 33 c0 [2] 2d dd [2] 2f dc [2] 34 da [2] 28 dd [2] 34 f2 }

  condition:
    any of them
}