rule TTP_XOR_QUAD_CurrentVersionRun_f1a6 {
  strings:
    $key_f1a6 = { a2 c9 [2] 86 c7 [2] ad eb [2] 83 c9 [2] 97 d2 [2] 98 c8 [2] 86 d5 [2] 84 d4 [2] 9f d2 [2] 83 d5 [2] 9f fa }

  condition:
    any of them
}