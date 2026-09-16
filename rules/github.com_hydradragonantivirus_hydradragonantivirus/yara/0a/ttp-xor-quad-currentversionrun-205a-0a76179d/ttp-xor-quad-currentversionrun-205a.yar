rule TTP_XOR_QUAD_CurrentVersionRun_205a {
  strings:
    $key_205a = { 73 35 [2] 57 3b [2] 7c 17 [2] 52 35 [2] 46 2e [2] 49 34 [2] 57 29 [2] 55 28 [2] 4e 2e [2] 52 29 [2] 4e 06 }

  condition:
    any of them
}