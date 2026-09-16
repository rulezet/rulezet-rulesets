rule TTP_XOR_QUAD_CurrentVersionRun_5496 {
  strings:
    $key_5496 = { 07 f9 [2] 23 f7 [2] 08 db [2] 26 f9 [2] 32 e2 [2] 3d f8 [2] 23 e5 [2] 21 e4 [2] 3a e2 [2] 26 e5 [2] 3a ca }

  condition:
    any of them
}