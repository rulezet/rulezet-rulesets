rule TTP_XOR_QUAD_CurrentVersionRun_60b3 {
  strings:
    $key_60b3 = { 33 dc [2] 17 d2 [2] 3c fe [2] 12 dc [2] 06 c7 [2] 09 dd [2] 17 c0 [2] 15 c1 [2] 0e c7 [2] 12 c0 [2] 0e ef }

  condition:
    any of them
}