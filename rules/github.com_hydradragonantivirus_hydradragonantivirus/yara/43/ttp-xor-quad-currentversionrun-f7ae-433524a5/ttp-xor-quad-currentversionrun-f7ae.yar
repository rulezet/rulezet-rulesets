rule TTP_XOR_QUAD_CurrentVersionRun_f7ae {
  strings:
    $key_f7ae = { a4 c1 [2] 80 cf [2] ab e3 [2] 85 c1 [2] 91 da [2] 9e c0 [2] 80 dd [2] 82 dc [2] 99 da [2] 85 dd [2] 99 f2 }

  condition:
    any of them
}