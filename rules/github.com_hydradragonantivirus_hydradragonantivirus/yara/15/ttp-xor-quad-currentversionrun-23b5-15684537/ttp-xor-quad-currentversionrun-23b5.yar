rule TTP_XOR_QUAD_CurrentVersionRun_23b5 {
  strings:
    $key_23b5 = { 70 da [2] 54 d4 [2] 7f f8 [2] 51 da [2] 45 c1 [2] 4a db [2] 54 c6 [2] 56 c7 [2] 4d c1 [2] 51 c6 [2] 4d e9 }

  condition:
    any of them
}