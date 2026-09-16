rule TTP_XOR_QUAD_CurrentVersionRun_168a {
  strings:
    $key_168a = { 45 e5 [2] 61 eb [2] 4a c7 [2] 64 e5 [2] 70 fe [2] 7f e4 [2] 61 f9 [2] 63 f8 [2] 78 fe [2] 64 f9 [2] 78 d6 }

  condition:
    any of them
}