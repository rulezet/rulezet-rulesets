rule TTP_XOR_QUAD_CurrentVersionRun_21b4 {
  strings:
    $key_21b4 = { 72 db [2] 56 d5 [2] 7d f9 [2] 53 db [2] 47 c0 [2] 48 da [2] 56 c7 [2] 54 c6 [2] 4f c0 [2] 53 c7 [2] 4f e8 }

  condition:
    any of them
}