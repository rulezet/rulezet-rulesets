rule TTP_XOR_QUAD_CurrentVersionRun_758a {
  strings:
    $key_758a = { 26 e5 [2] 02 eb [2] 29 c7 [2] 07 e5 [2] 13 fe [2] 1c e4 [2] 02 f9 [2] 00 f8 [2] 1b fe [2] 07 f9 [2] 1b d6 }

  condition:
    any of them
}