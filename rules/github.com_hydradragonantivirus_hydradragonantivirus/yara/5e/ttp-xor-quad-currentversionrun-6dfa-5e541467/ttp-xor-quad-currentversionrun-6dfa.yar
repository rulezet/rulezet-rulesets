rule TTP_XOR_QUAD_CurrentVersionRun_6dfa {
  strings:
    $key_6dfa = { 3e 95 [2] 1a 9b [2] 31 b7 [2] 1f 95 [2] 0b 8e [2] 04 94 [2] 1a 89 [2] 18 88 [2] 03 8e [2] 1f 89 [2] 03 a6 }

  condition:
    any of them
}