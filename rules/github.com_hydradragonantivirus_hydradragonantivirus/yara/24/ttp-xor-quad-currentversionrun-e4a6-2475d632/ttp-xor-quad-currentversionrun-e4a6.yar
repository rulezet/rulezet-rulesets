rule TTP_XOR_QUAD_CurrentVersionRun_e4a6 {
  strings:
    $key_e4a6 = { b7 c9 [2] 93 c7 [2] b8 eb [2] 96 c9 [2] 82 d2 [2] 8d c8 [2] 93 d5 [2] 91 d4 [2] 8a d2 [2] 96 d5 [2] 8a fa }

  condition:
    any of them
}