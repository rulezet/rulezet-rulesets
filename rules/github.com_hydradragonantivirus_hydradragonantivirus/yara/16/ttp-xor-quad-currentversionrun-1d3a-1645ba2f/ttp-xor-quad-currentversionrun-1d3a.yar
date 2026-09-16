rule TTP_XOR_QUAD_CurrentVersionRun_1d3a {
  strings:
    $key_1d3a = { 4e 55 [2] 6a 5b [2] 41 77 [2] 6f 55 [2] 7b 4e [2] 74 54 [2] 6a 49 [2] 68 48 [2] 73 4e [2] 6f 49 [2] 73 66 }

  condition:
    any of them
}