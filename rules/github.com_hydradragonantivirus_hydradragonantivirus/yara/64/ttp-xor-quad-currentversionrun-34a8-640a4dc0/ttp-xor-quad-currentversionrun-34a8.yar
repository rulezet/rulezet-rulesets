rule TTP_XOR_QUAD_CurrentVersionRun_34a8 {
  strings:
    $key_34a8 = { 67 c7 [2] 43 c9 [2] 68 e5 [2] 46 c7 [2] 52 dc [2] 5d c6 [2] 43 db [2] 41 da [2] 5a dc [2] 46 db [2] 5a f4 }

  condition:
    any of them
}