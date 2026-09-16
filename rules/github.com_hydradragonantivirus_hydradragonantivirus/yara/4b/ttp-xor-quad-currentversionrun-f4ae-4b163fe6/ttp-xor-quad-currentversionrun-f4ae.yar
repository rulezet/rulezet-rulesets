rule TTP_XOR_QUAD_CurrentVersionRun_f4ae {
  strings:
    $key_f4ae = { a7 c1 [2] 83 cf [2] a8 e3 [2] 86 c1 [2] 92 da [2] 9d c0 [2] 83 dd [2] 81 dc [2] 9a da [2] 86 dd [2] 9a f2 }

  condition:
    any of them
}