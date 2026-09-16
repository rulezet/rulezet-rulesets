rule TTP_XOR_QUAD_CurrentVersionRun_105a {
  strings:
    $key_105a = { 43 35 [2] 67 3b [2] 4c 17 [2] 62 35 [2] 76 2e [2] 79 34 [2] 67 29 [2] 65 28 [2] 7e 2e [2] 62 29 [2] 7e 06 }

  condition:
    any of them
}