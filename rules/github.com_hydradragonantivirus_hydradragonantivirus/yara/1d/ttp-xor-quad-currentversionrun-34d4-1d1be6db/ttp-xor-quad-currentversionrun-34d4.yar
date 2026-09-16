rule TTP_XOR_QUAD_CurrentVersionRun_34d4 {
  strings:
    $key_34d4 = { 67 bb [2] 43 b5 [2] 68 99 [2] 46 bb [2] 52 a0 [2] 5d ba [2] 43 a7 [2] 41 a6 [2] 5a a0 [2] 46 a7 [2] 5a 88 }

  condition:
    any of them
}