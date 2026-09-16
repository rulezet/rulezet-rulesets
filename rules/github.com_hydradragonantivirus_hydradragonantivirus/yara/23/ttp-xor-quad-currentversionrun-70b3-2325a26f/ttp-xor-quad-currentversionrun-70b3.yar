rule TTP_XOR_QUAD_CurrentVersionRun_70b3 {
  strings:
    $key_70b3 = { 23 dc [2] 07 d2 [2] 2c fe [2] 02 dc [2] 16 c7 [2] 19 dd [2] 07 c0 [2] 05 c1 [2] 1e c7 [2] 02 c0 [2] 1e ef }

  condition:
    any of them
}