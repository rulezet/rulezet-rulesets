rule TTP_XOR_QUAD_CurrentVersionRun_3ab4 {
  strings:
    $key_3ab4 = { 69 db [2] 4d d5 [2] 66 f9 [2] 48 db [2] 5c c0 [2] 53 da [2] 4d c7 [2] 4f c6 [2] 54 c0 [2] 48 c7 [2] 54 e8 }

  condition:
    any of them
}