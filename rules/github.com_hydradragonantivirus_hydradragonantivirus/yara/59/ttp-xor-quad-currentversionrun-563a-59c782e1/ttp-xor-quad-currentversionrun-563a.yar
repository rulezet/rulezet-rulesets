rule TTP_XOR_QUAD_CurrentVersionRun_563a {
  strings:
    $key_563a = { 05 55 [2] 21 5b [2] 0a 77 [2] 24 55 [2] 30 4e [2] 3f 54 [2] 21 49 [2] 23 48 [2] 38 4e [2] 24 49 [2] 38 66 }

  condition:
    any of them
}