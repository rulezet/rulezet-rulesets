rule TTP_XOR_QUAD_CurrentVersionRun_104a {
  strings:
    $key_104a = { 43 25 [2] 67 2b [2] 4c 07 [2] 62 25 [2] 76 3e [2] 79 24 [2] 67 39 [2] 65 38 [2] 7e 3e [2] 62 39 [2] 7e 16 }

  condition:
    any of them
}