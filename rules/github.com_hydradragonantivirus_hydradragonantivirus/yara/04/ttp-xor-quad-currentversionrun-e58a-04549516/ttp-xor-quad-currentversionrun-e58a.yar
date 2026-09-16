rule TTP_XOR_QUAD_CurrentVersionRun_e58a {
  strings:
    $key_e58a = { b6 e5 [2] 92 eb [2] b9 c7 [2] 97 e5 [2] 83 fe [2] 8c e4 [2] 92 f9 [2] 90 f8 [2] 8b fe [2] 97 f9 [2] 8b d6 }

  condition:
    any of them
}