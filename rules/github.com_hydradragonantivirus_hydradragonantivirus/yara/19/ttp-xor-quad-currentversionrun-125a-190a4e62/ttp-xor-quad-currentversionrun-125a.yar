rule TTP_XOR_QUAD_CurrentVersionRun_125a {
  strings:
    $key_125a = { 41 35 [2] 65 3b [2] 4e 17 [2] 60 35 [2] 74 2e [2] 7b 34 [2] 65 29 [2] 67 28 [2] 7c 2e [2] 60 29 [2] 7c 06 }

  condition:
    any of them
}