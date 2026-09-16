rule TTP_XOR_QUAD_CurrentVersionRun_5d3a {
  strings:
    $key_5d3a = { 0e 55 [2] 2a 5b [2] 01 77 [2] 2f 55 [2] 3b 4e [2] 34 54 [2] 2a 49 [2] 28 48 [2] 33 4e [2] 2f 49 [2] 33 66 }

  condition:
    any of them
}