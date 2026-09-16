rule TTP_XOR_QUAD_CurrentVersionRun_478a {
  strings:
    $key_478a = { 14 e5 [2] 30 eb [2] 1b c7 [2] 35 e5 [2] 21 fe [2] 2e e4 [2] 30 f9 [2] 32 f8 [2] 29 fe [2] 35 f9 [2] 29 d6 }

  condition:
    any of them
}