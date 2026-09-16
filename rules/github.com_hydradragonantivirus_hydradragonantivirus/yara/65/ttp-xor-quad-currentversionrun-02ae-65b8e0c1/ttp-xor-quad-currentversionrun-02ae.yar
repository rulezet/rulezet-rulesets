rule TTP_XOR_QUAD_CurrentVersionRun_02ae {
  strings:
    $key_02ae = { 51 c1 [2] 75 cf [2] 5e e3 [2] 70 c1 [2] 64 da [2] 6b c0 [2] 75 dd [2] 77 dc [2] 6c da [2] 70 dd [2] 6c f2 }

  condition:
    any of them
}