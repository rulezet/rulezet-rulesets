rule TTP_XOR_QUAD_CurrentVersionRun_21b5 {
  strings:
    $key_21b5 = { 72 da [2] 56 d4 [2] 7d f8 [2] 53 da [2] 47 c1 [2] 48 db [2] 56 c6 [2] 54 c7 [2] 4f c1 [2] 53 c6 [2] 4f e9 }

  condition:
    any of them
}