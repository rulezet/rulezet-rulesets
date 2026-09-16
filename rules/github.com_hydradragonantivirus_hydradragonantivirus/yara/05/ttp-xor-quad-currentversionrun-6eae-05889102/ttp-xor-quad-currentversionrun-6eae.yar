rule TTP_XOR_QUAD_CurrentVersionRun_6eae {
  strings:
    $key_6eae = { 3d c1 [2] 19 cf [2] 32 e3 [2] 1c c1 [2] 08 da [2] 07 c0 [2] 19 dd [2] 1b dc [2] 00 da [2] 1c dd [2] 00 f2 }

  condition:
    any of them
}