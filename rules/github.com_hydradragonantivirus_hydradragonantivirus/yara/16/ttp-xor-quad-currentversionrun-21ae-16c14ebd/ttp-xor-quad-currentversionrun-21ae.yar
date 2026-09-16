rule TTP_XOR_QUAD_CurrentVersionRun_21ae {
  strings:
    $key_21ae = { 72 c1 [2] 56 cf [2] 7d e3 [2] 53 c1 [2] 47 da [2] 48 c0 [2] 56 dd [2] 54 dc [2] 4f da [2] 53 dd [2] 4f f2 }

  condition:
    any of them
}