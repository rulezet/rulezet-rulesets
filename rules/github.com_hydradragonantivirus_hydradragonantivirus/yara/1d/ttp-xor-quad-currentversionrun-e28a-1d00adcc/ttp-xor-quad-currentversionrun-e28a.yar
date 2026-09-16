rule TTP_XOR_QUAD_CurrentVersionRun_e28a {
  strings:
    $key_e28a = { b1 e5 [2] 95 eb [2] be c7 [2] 90 e5 [2] 84 fe [2] 8b e4 [2] 95 f9 [2] 97 f8 [2] 8c fe [2] 90 f9 [2] 8c d6 }

  condition:
    any of them
}