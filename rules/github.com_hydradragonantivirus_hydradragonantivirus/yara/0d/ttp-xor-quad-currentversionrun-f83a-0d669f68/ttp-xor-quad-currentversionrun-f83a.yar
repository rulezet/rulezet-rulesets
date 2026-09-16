rule TTP_XOR_QUAD_CurrentVersionRun_f83a {
  strings:
    $key_f83a = { ab 55 [2] 8f 5b [2] a4 77 [2] 8a 55 [2] 9e 4e [2] 91 54 [2] 8f 49 [2] 8d 48 [2] 96 4e [2] 8a 49 [2] 96 66 }

  condition:
    any of them
}