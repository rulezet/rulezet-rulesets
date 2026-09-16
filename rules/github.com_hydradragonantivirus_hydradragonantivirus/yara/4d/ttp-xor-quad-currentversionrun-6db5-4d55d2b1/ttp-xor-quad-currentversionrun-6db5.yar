rule TTP_XOR_QUAD_CurrentVersionRun_6db5 {
  strings:
    $key_6db5 = { 3e da [2] 1a d4 [2] 31 f8 [2] 1f da [2] 0b c1 [2] 04 db [2] 1a c6 [2] 18 c7 [2] 03 c1 [2] 1f c6 [2] 03 e9 }

  condition:
    any of them
}