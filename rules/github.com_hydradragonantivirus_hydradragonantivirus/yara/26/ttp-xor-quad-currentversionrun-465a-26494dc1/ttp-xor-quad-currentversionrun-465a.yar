rule TTP_XOR_QUAD_CurrentVersionRun_465a {
  strings:
    $key_465a = { 15 35 [2] 31 3b [2] 1a 17 [2] 34 35 [2] 20 2e [2] 2f 34 [2] 31 29 [2] 33 28 [2] 28 2e [2] 34 29 [2] 28 06 }

  condition:
    any of them
}