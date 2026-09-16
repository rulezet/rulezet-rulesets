rule TTP_XOR_QUAD_CurrentVersionRun_0e5a {
  strings:
    $key_0e5a = { 5d 35 [2] 79 3b [2] 52 17 [2] 7c 35 [2] 68 2e [2] 67 34 [2] 79 29 [2] 7b 28 [2] 60 2e [2] 7c 29 [2] 60 06 }

  condition:
    any of them
}