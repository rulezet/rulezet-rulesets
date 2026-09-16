rule TTP_XOR_QUAD_CurrentVersionRun_0cfa {
  strings:
    $key_0cfa = { 5f 95 [2] 7b 9b [2] 50 b7 [2] 7e 95 [2] 6a 8e [2] 65 94 [2] 7b 89 [2] 79 88 [2] 62 8e [2] 7e 89 [2] 62 a6 }

  condition:
    any of them
}