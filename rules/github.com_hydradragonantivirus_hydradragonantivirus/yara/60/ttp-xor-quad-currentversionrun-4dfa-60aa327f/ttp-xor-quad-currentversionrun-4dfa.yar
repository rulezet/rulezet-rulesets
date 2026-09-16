rule TTP_XOR_QUAD_CurrentVersionRun_4dfa {
  strings:
    $key_4dfa = { 1e 95 [2] 3a 9b [2] 11 b7 [2] 3f 95 [2] 2b 8e [2] 24 94 [2] 3a 89 [2] 38 88 [2] 23 8e [2] 3f 89 [2] 23 a6 }

  condition:
    any of them
}