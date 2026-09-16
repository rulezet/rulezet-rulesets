rule TTP_XOR_QUAD_CurrentVersionRun_f13a {
  strings:
    $key_f13a = { a2 55 [2] 86 5b [2] ad 77 [2] 83 55 [2] 97 4e [2] 98 54 [2] 86 49 [2] 84 48 [2] 9f 4e [2] 83 49 [2] 9f 66 }

  condition:
    any of them
}