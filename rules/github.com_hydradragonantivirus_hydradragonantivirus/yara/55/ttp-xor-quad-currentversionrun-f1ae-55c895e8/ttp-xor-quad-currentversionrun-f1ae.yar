rule TTP_XOR_QUAD_CurrentVersionRun_f1ae {
  strings:
    $key_f1ae = { a2 c1 [2] 86 cf [2] ad e3 [2] 83 c1 [2] 97 da [2] 98 c0 [2] 86 dd [2] 84 dc [2] 9f da [2] 83 dd [2] 9f f2 }

  condition:
    any of them
}