rule TTP_XOR_QUAD_CurrentVersionRun_e2a6 {
  strings:
    $key_e2a6 = { b1 c9 [2] 95 c7 [2] be eb [2] 90 c9 [2] 84 d2 [2] 8b c8 [2] 95 d5 [2] 97 d4 [2] 8c d2 [2] 90 d5 [2] 8c fa }

  condition:
    any of them
}