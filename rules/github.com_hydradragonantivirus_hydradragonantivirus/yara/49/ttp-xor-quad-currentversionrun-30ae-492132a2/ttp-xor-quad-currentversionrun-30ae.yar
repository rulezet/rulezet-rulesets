rule TTP_XOR_QUAD_CurrentVersionRun_30ae {
  strings:
    $key_30ae = { 63 c1 [2] 47 cf [2] 6c e3 [2] 42 c1 [2] 56 da [2] 59 c0 [2] 47 dd [2] 45 dc [2] 5e da [2] 42 dd [2] 5e f2 }

  condition:
    any of them
}