rule TTP_XOR_QUAD_CurrentVersionRun_308a {
  strings:
    $key_308a = { 63 e5 [2] 47 eb [2] 6c c7 [2] 42 e5 [2] 56 fe [2] 59 e4 [2] 47 f9 [2] 45 f8 [2] 5e fe [2] 42 f9 [2] 5e d6 }

  condition:
    any of them
}