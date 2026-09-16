rule TTP_XOR_QUAD_CurrentVersionRun_14a8 {
  strings:
    $key_14a8 = { 47 c7 [2] 63 c9 [2] 48 e5 [2] 66 c7 [2] 72 dc [2] 7d c6 [2] 63 db [2] 61 da [2] 7a dc [2] 66 db [2] 7a f4 }

  condition:
    any of them
}