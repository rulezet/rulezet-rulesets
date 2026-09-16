rule TTP_XOR_QUAD_CurrentVersionRun_30b3 {
  strings:
    $key_30b3 = { 63 dc [2] 47 d2 [2] 6c fe [2] 42 dc [2] 56 c7 [2] 59 dd [2] 47 c0 [2] 45 c1 [2] 5e c7 [2] 42 c0 [2] 5e ef }

  condition:
    any of them
}