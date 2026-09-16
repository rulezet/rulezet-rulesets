rule TTP_XOR_QUAD_CurrentVersionRun_f6ae {
  strings:
    $key_f6ae = { a5 c1 [2] 81 cf [2] aa e3 [2] 84 c1 [2] 90 da [2] 9f c0 [2] 81 dd [2] 83 dc [2] 98 da [2] 84 dd [2] 98 f2 }

  condition:
    any of them
}