rule TTP_XOR_QUAD_CurrentVersionRun_148a {
  strings:
    $key_148a = { 47 e5 [2] 63 eb [2] 48 c7 [2] 66 e5 [2] 72 fe [2] 7d e4 [2] 63 f9 [2] 61 f8 [2] 7a fe [2] 66 f9 [2] 7a d6 }

  condition:
    any of them
}