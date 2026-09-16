rule TTP_XOR_QUAD_CurrentVersionRun_0ffa {
  strings:
    $key_0ffa = { 5c 95 [2] 78 9b [2] 53 b7 [2] 7d 95 [2] 69 8e [2] 66 94 [2] 78 89 [2] 7a 88 [2] 61 8e [2] 7d 89 [2] 61 a6 }

  condition:
    any of them
}