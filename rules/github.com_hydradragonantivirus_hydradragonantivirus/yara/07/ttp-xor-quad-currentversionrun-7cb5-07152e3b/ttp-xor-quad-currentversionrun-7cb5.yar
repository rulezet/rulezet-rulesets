rule TTP_XOR_QUAD_CurrentVersionRun_7cb5 {
  strings:
    $key_7cb5 = { 2f da [2] 0b d4 [2] 20 f8 [2] 0e da [2] 1a c1 [2] 15 db [2] 0b c6 [2] 09 c7 [2] 12 c1 [2] 0e c6 [2] 12 e9 }

  condition:
    any of them
}