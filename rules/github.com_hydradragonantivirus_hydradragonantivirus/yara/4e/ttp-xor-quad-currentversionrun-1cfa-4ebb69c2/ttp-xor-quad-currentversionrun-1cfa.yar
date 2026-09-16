rule TTP_XOR_QUAD_CurrentVersionRun_1cfa {
  strings:
    $key_1cfa = { 4f 95 [2] 6b 9b [2] 40 b7 [2] 6e 95 [2] 7a 8e [2] 75 94 [2] 6b 89 [2] 69 88 [2] 72 8e [2] 6e 89 [2] 72 a6 }

  condition:
    any of them
}