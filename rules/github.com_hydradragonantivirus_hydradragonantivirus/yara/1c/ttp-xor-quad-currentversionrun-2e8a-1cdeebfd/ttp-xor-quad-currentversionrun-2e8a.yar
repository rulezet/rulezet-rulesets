rule TTP_XOR_QUAD_CurrentVersionRun_2e8a {
  strings:
    $key_2e8a = { 7d e5 [2] 59 eb [2] 72 c7 [2] 5c e5 [2] 48 fe [2] 47 e4 [2] 59 f9 [2] 5b f8 [2] 40 fe [2] 5c f9 [2] 40 d6 }

  condition:
    any of them
}