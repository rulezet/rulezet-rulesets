rule TTP_XOR_QUAD_CurrentVersionRun_61ae {
  strings:
    $key_61ae = { 32 c1 [2] 16 cf [2] 3d e3 [2] 13 c1 [2] 07 da [2] 08 c0 [2] 16 dd [2] 14 dc [2] 0f da [2] 13 dd [2] 0f f2 }

  condition:
    any of them
}