rule TTP_XOR_QUAD_CurrentVersionRun_7eae {
  strings:
    $key_7eae = { 2d c1 [2] 09 cf [2] 22 e3 [2] 0c c1 [2] 18 da [2] 17 c0 [2] 09 dd [2] 0b dc [2] 10 da [2] 0c dd [2] 10 f2 }

  condition:
    any of them
}