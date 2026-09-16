rule TTP_XOR_QUAD_CurrentVersionRun_095a {
  strings:
    $key_095a = { 5a 35 [2] 7e 3b [2] 55 17 [2] 7b 35 [2] 6f 2e [2] 60 34 [2] 7e 29 [2] 7c 28 [2] 67 2e [2] 7b 29 [2] 67 06 }

  condition:
    any of them
}