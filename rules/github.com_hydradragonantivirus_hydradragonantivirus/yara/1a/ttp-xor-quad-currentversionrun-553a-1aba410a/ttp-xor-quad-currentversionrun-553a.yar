rule TTP_XOR_QUAD_CurrentVersionRun_553a {
  strings:
    $key_553a = { 06 55 [2] 22 5b [2] 09 77 [2] 27 55 [2] 33 4e [2] 3c 54 [2] 22 49 [2] 20 48 [2] 3b 4e [2] 27 49 [2] 3b 66 }

  condition:
    any of them
}