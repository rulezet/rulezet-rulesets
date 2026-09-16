rule TTP_XOR_QUAD_CurrentVersionRun_50b3 {
  strings:
    $key_50b3 = { 03 dc [2] 27 d2 [2] 0c fe [2] 22 dc [2] 36 c7 [2] 39 dd [2] 27 c0 [2] 25 c1 [2] 3e c7 [2] 22 c0 [2] 3e ef }

  condition:
    any of them
}