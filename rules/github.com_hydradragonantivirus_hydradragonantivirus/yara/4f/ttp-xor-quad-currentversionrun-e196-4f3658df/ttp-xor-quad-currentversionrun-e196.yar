rule TTP_XOR_QUAD_CurrentVersionRun_e196 {
  strings:
    $key_e196 = { b2 f9 [2] 96 f7 [2] bd db [2] 93 f9 [2] 87 e2 [2] 88 f8 [2] 96 e5 [2] 94 e4 [2] 8f e2 [2] 93 e5 [2] 8f ca }

  condition:
    any of them
}