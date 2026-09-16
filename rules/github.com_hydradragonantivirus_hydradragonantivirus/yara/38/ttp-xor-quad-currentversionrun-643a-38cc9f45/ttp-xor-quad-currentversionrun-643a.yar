rule TTP_XOR_QUAD_CurrentVersionRun_643a {
  strings:
    $key_643a = { 37 55 [2] 13 5b [2] 38 77 [2] 16 55 [2] 02 4e [2] 0d 54 [2] 13 49 [2] 11 48 [2] 0a 4e [2] 16 49 [2] 0a 66 }

  condition:
    any of them
}