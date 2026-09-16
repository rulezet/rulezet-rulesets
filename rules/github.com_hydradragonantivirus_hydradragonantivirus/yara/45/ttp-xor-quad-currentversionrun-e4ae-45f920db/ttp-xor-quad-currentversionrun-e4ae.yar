rule TTP_XOR_QUAD_CurrentVersionRun_e4ae {
  strings:
    $key_e4ae = { b7 c1 [2] 93 cf [2] b8 e3 [2] 96 c1 [2] 82 da [2] 8d c0 [2] 93 dd [2] 91 dc [2] 8a da [2] 96 dd [2] 8a f2 }

  condition:
    any of them
}