rule TTP_XOR_QUAD_CurrentVersionRun_10ae {
  strings:
    $key_10ae = { 43 c1 [2] 67 cf [2] 4c e3 [2] 62 c1 [2] 76 da [2] 79 c0 [2] 67 dd [2] 65 dc [2] 7e da [2] 62 dd [2] 7e f2 }

  condition:
    any of them
}