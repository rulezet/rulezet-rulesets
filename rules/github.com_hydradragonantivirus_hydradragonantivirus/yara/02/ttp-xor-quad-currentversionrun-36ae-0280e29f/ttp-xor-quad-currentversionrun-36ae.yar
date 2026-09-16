rule TTP_XOR_QUAD_CurrentVersionRun_36ae {
  strings:
    $key_36ae = { 65 c1 [2] 41 cf [2] 6a e3 [2] 44 c1 [2] 50 da [2] 5f c0 [2] 41 dd [2] 43 dc [2] 58 da [2] 44 dd [2] 58 f2 }

  condition:
    any of them
}