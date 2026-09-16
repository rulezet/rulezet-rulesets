rule TTP_XOR_QUAD_CurrentVersionRun_3596 {
  strings:
    $key_3596 = { 66 f9 [2] 42 f7 [2] 69 db [2] 47 f9 [2] 53 e2 [2] 5c f8 [2] 42 e5 [2] 40 e4 [2] 5b e2 [2] 47 e5 [2] 5b ca }

  condition:
    any of them
}