rule TTP_XOR_QUAD_CurrentVersionRun_32ae {
  strings:
    $key_32ae = { 61 c1 [2] 45 cf [2] 6e e3 [2] 40 c1 [2] 54 da [2] 5b c0 [2] 45 dd [2] 47 dc [2] 5c da [2] 40 dd [2] 5c f2 }

  condition:
    any of them
}