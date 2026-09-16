rule TTP_XOR_QUAD_CurrentVersionRun_1196 {
  strings:
    $key_1196 = { 42 f9 [2] 66 f7 [2] 4d db [2] 63 f9 [2] 77 e2 [2] 78 f8 [2] 66 e5 [2] 64 e4 [2] 7f e2 [2] 63 e5 [2] 7f ca }

  condition:
    any of them
}