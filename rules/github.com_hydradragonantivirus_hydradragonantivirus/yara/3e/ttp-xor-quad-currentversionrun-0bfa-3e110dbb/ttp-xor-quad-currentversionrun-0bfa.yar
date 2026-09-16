rule TTP_XOR_QUAD_CurrentVersionRun_0bfa {
  strings:
    $key_0bfa = { 58 95 [2] 7c 9b [2] 57 b7 [2] 79 95 [2] 6d 8e [2] 62 94 [2] 7c 89 [2] 7e 88 [2] 65 8e [2] 79 89 [2] 65 a6 }

  condition:
    any of them
}