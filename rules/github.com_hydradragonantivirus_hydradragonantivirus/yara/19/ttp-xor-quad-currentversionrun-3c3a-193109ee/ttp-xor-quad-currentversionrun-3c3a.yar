rule TTP_XOR_QUAD_CurrentVersionRun_3c3a {
  strings:
    $key_3c3a = { 6f 55 [2] 4b 5b [2] 60 77 [2] 4e 55 [2] 5a 4e [2] 55 54 [2] 4b 49 [2] 49 48 [2] 52 4e [2] 4e 49 [2] 52 66 }

  condition:
    any of them
}