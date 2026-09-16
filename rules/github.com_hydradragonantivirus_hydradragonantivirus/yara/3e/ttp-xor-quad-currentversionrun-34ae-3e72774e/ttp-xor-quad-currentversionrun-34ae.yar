rule TTP_XOR_QUAD_CurrentVersionRun_34ae {
  strings:
    $key_34ae = { 67 c1 [2] 43 cf [2] 68 e3 [2] 46 c1 [2] 52 da [2] 5d c0 [2] 43 dd [2] 41 dc [2] 5a da [2] 46 dd [2] 5a f2 }

  condition:
    any of them
}