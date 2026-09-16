rule TTP_XOR_QUAD_CurrentVersionRun_3b5a {
  strings:
    $key_3b5a = { 68 35 [2] 4c 3b [2] 67 17 [2] 49 35 [2] 5d 2e [2] 52 34 [2] 4c 29 [2] 4e 28 [2] 55 2e [2] 49 29 [2] 55 06 }

  condition:
    any of them
}