rule TTP_XOR_QUAD_CurrentVersionRun_603a {
  strings:
    $key_603a = { 33 55 [2] 17 5b [2] 3c 77 [2] 12 55 [2] 06 4e [2] 09 54 [2] 17 49 [2] 15 48 [2] 0e 4e [2] 12 49 [2] 0e 66 }

  condition:
    any of them
}