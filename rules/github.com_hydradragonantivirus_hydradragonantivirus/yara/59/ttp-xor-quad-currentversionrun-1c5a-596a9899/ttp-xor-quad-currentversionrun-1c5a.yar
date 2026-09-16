rule TTP_XOR_QUAD_CurrentVersionRun_1c5a {
  strings:
    $key_1c5a = { 4f 35 [2] 6b 3b [2] 40 17 [2] 6e 35 [2] 7a 2e [2] 75 34 [2] 6b 29 [2] 69 28 [2] 72 2e [2] 6e 29 [2] 72 06 }

  condition:
    any of them
}