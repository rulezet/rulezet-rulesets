rule TTP_XOR_QUAD_CurrentVersionRun_f68a {
  strings:
    $key_f68a = { a5 e5 [2] 81 eb [2] aa c7 [2] 84 e5 [2] 90 fe [2] 9f e4 [2] 81 f9 [2] 83 f8 [2] 98 fe [2] 84 f9 [2] 98 d6 }

  condition:
    any of them
}