rule TTP_XOR_QUAD_CurrentVersionRun_01ae {
  strings:
    $key_01ae = { 52 c1 [2] 76 cf [2] 5d e3 [2] 73 c1 [2] 67 da [2] 68 c0 [2] 76 dd [2] 74 dc [2] 6f da [2] 73 dd [2] 6f f2 }

  condition:
    any of them
}