rule TTP_XOR_QUAD_CurrentVersionRun_6cfa {
  strings:
    $key_6cfa = { 3f 95 [2] 1b 9b [2] 30 b7 [2] 1e 95 [2] 0a 8e [2] 05 94 [2] 1b 89 [2] 19 88 [2] 02 8e [2] 1e 89 [2] 02 a6 }

  condition:
    any of them
}