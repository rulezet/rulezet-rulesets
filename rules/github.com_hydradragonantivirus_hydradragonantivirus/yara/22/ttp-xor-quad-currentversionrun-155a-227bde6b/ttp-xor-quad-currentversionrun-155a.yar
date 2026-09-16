rule TTP_XOR_QUAD_CurrentVersionRun_155a {
  strings:
    $key_155a = { 46 35 [2] 62 3b [2] 49 17 [2] 67 35 [2] 73 2e [2] 7c 34 [2] 62 29 [2] 60 28 [2] 7b 2e [2] 67 29 [2] 7b 06 }

  condition:
    any of them
}