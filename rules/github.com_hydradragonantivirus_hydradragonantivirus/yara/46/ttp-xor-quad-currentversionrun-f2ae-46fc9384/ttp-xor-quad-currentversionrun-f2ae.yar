rule TTP_XOR_QUAD_CurrentVersionRun_f2ae {
  strings:
    $key_f2ae = { a1 c1 [2] 85 cf [2] ae e3 [2] 80 c1 [2] 94 da [2] 9b c0 [2] 85 dd [2] 87 dc [2] 9c da [2] 80 dd [2] 9c f2 }

  condition:
    any of them
}