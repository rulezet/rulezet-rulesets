rule TTP_XOR_QUAD_CurrentVersionRun_24ae {
  strings:
    $key_24ae = { 77 c1 [2] 53 cf [2] 78 e3 [2] 56 c1 [2] 42 da [2] 4d c0 [2] 53 dd [2] 51 dc [2] 4a da [2] 56 dd [2] 4a f2 }

  condition:
    any of them
}