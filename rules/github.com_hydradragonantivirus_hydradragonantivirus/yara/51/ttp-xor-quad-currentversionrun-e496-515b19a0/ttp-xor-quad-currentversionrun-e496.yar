rule TTP_XOR_QUAD_CurrentVersionRun_e496 {
  strings:
    $key_e496 = { b7 f9 [2] 93 f7 [2] b8 db [2] 96 f9 [2] 82 e2 [2] 8d f8 [2] 93 e5 [2] 91 e4 [2] 8a e2 [2] 96 e5 [2] 8a ca }

  condition:
    any of them
}