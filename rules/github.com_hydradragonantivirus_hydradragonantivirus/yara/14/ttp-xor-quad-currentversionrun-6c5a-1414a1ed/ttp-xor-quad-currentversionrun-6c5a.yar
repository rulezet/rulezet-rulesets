rule TTP_XOR_QUAD_CurrentVersionRun_6c5a {
  strings:
    $key_6c5a = { 3f 35 [2] 1b 3b [2] 30 17 [2] 1e 35 [2] 0a 2e [2] 05 34 [2] 1b 29 [2] 19 28 [2] 02 2e [2] 1e 29 [2] 02 06 }

  condition:
    any of them
}