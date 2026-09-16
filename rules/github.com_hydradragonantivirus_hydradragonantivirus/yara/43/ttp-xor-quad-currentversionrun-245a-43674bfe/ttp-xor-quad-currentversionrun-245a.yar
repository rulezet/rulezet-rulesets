rule TTP_XOR_QUAD_CurrentVersionRun_245a {
  strings:
    $key_245a = { 77 35 [2] 53 3b [2] 78 17 [2] 56 35 [2] 42 2e [2] 4d 34 [2] 53 29 [2] 51 28 [2] 4a 2e [2] 56 29 [2] 4a 06 }

  condition:
    any of them
}