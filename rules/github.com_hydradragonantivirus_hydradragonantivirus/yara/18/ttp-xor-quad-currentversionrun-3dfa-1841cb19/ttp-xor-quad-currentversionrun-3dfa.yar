rule TTP_XOR_QUAD_CurrentVersionRun_3dfa {
  strings:
    $key_3dfa = { 6e 95 [2] 4a 9b [2] 61 b7 [2] 4f 95 [2] 5b 8e [2] 54 94 [2] 4a 89 [2] 48 88 [2] 53 8e [2] 4f 89 [2] 53 a6 }

  condition:
    any of them
}