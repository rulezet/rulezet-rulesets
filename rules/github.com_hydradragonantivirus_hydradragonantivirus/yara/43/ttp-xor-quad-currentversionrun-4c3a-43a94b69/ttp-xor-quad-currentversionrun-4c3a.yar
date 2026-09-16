rule TTP_XOR_QUAD_CurrentVersionRun_4c3a {
  strings:
    $key_4c3a = { 1f 55 [2] 3b 5b [2] 10 77 [2] 3e 55 [2] 2a 4e [2] 25 54 [2] 3b 49 [2] 39 48 [2] 22 4e [2] 3e 49 [2] 22 66 }

  condition:
    any of them
}