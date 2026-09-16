rule TTP_XOR_QUAD_CurrentVersionRun_24a8 {
  strings:
    $key_24a8 = { 77 c7 [2] 53 c9 [2] 78 e5 [2] 56 c7 [2] 42 dc [2] 4d c6 [2] 53 db [2] 51 da [2] 4a dc [2] 56 db [2] 4a f4 }

  condition:
    any of them
}