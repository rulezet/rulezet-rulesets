rule TTP_XOR_QUAD_CurrentVersionRun_fab6 {
  strings:
    $key_fab6 = { a9 d9 [2] 8d d7 [2] a6 fb [2] 88 d9 [2] 9c c2 [2] 93 d8 [2] 8d c5 [2] 8f c4 [2] 94 c2 [2] 88 c5 [2] 94 ea }

  condition:
    any of them
}