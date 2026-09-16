rule TTP_XOR_QUAD_CurrentVersionRun_7db5 {
  strings:
    $key_7db5 = { 2e da [2] 0a d4 [2] 21 f8 [2] 0f da [2] 1b c1 [2] 14 db [2] 0a c6 [2] 08 c7 [2] 13 c1 [2] 0f c6 [2] 13 e9 }

  condition:
    any of them
}