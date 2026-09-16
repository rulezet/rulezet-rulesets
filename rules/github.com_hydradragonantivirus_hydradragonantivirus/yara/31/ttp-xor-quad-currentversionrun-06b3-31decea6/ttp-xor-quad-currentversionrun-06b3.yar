rule TTP_XOR_QUAD_CurrentVersionRun_06b3 {
  strings:
    $key_06b3 = { 55 dc [2] 71 d2 [2] 5a fe [2] 74 dc [2] 60 c7 [2] 6f dd [2] 71 c0 [2] 73 c1 [2] 68 c7 [2] 74 c0 [2] 68 ef }

  condition:
    any of them
}