rule TTP_XOR_QUAD_CurrentVersionRun_43b4 {
  strings:
    $key_43b4 = { 10 db [2] 34 d5 [2] 1f f9 [2] 31 db [2] 25 c0 [2] 2a da [2] 34 c7 [2] 36 c6 [2] 2d c0 [2] 31 c7 [2] 2d e8 }

  condition:
    any of them
}