rule TTP_XOR_QUAD_CurrentVersionRun_3eae {
  strings:
    $key_3eae = { 6d c1 [2] 49 cf [2] 62 e3 [2] 4c c1 [2] 58 da [2] 57 c0 [2] 49 dd [2] 4b dc [2] 50 da [2] 4c dd [2] 50 f2 }

  condition:
    any of them
}