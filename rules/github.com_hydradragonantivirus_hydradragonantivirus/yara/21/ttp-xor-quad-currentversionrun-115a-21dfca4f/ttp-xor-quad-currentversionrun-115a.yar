rule TTP_XOR_QUAD_CurrentVersionRun_115a {
  strings:
    $key_115a = { 42 35 [2] 66 3b [2] 4d 17 [2] 63 35 [2] 77 2e [2] 78 34 [2] 66 29 [2] 64 28 [2] 7f 2e [2] 63 29 [2] 7f 06 }

  condition:
    any of them
}