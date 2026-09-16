rule TTP_XOR_QUAD_CurrentVersionRun_5dfa {
  strings:
    $key_5dfa = { 0e 95 [2] 2a 9b [2] 01 b7 [2] 2f 95 [2] 3b 8e [2] 34 94 [2] 2a 89 [2] 28 88 [2] 33 8e [2] 2f 89 [2] 33 a6 }

  condition:
    any of them
}