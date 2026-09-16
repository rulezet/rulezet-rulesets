rule TTP_XOR_QUAD_CurrentVersionRun_66b3 {
  strings:
    $key_66b3 = { 35 dc [2] 11 d2 [2] 3a fe [2] 14 dc [2] 00 c7 [2] 0f dd [2] 11 c0 [2] 13 c1 [2] 08 c7 [2] 14 c0 [2] 08 ef }

  condition:
    any of them
}