rule TTP_XOR_QUAD_CurrentVersionRun_7196 {
  strings:
    $key_7196 = { 22 f9 [2] 06 f7 [2] 2d db [2] 03 f9 [2] 17 e2 [2] 18 f8 [2] 06 e5 [2] 04 e4 [2] 1f e2 [2] 03 e5 [2] 1f ca }

  condition:
    any of them
}