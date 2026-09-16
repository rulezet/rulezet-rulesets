rule TTP_XOR_QUAD_CurrentVersionRun_26b3 {
  strings:
    $key_26b3 = { 75 dc [2] 51 d2 [2] 7a fe [2] 54 dc [2] 40 c7 [2] 4f dd [2] 51 c0 [2] 53 c1 [2] 48 c7 [2] 54 c0 [2] 48 ef }

  condition:
    any of them
}