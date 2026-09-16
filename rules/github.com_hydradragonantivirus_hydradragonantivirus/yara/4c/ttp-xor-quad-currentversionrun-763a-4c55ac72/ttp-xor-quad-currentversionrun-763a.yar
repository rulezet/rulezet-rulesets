rule TTP_XOR_QUAD_CurrentVersionRun_763a {
  strings:
    $key_763a = { 25 55 [2] 01 5b [2] 2a 77 [2] 04 55 [2] 10 4e [2] 1f 54 [2] 01 49 [2] 03 48 [2] 18 4e [2] 04 49 [2] 18 66 }

  condition:
    any of them
}