rule TTP_XOR_QUAD_CurrentVersionRun_47d1 {
  strings:
    $key_47d1 = { 14 be [2] 30 b0 [2] 1b 9c [2] 35 be [2] 21 a5 [2] 2e bf [2] 30 a2 [2] 32 a3 [2] 29 a5 [2] 35 a2 [2] 29 8d }

  condition:
    any of them
}