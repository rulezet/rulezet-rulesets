rule TTP_XOR_QUAD_CurrentVersionRun_0db5 {
  strings:
    $key_0db5 = { 5e da [2] 7a d4 [2] 51 f8 [2] 7f da [2] 6b c1 [2] 64 db [2] 7a c6 [2] 78 c7 [2] 63 c1 [2] 7f c6 [2] 63 e9 }

  condition:
    any of them
}