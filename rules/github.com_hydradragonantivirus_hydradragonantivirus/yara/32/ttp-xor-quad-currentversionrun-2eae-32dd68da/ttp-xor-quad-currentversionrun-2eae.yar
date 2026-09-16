rule TTP_XOR_QUAD_CurrentVersionRun_2eae {
  strings:
    $key_2eae = { 7d c1 [2] 59 cf [2] 72 e3 [2] 5c c1 [2] 48 da [2] 47 c0 [2] 59 dd [2] 5b dc [2] 40 da [2] 5c dd [2] 40 f2 }

  condition:
    any of them
}