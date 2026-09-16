rule TTP_XOR_QUAD_CurrentVersionRun_225a {
  strings:
    $key_225a = { 71 35 [2] 55 3b [2] 7e 17 [2] 50 35 [2] 44 2e [2] 4b 34 [2] 55 29 [2] 57 28 [2] 4c 2e [2] 50 29 [2] 4c 06 }

  condition:
    any of them
}