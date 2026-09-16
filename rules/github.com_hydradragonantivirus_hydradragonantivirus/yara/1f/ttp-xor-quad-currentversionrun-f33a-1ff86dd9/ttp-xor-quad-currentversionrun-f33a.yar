rule TTP_XOR_QUAD_CurrentVersionRun_f33a {
  strings:
    $key_f33a = { a0 55 [2] 84 5b [2] af 77 [2] 81 55 [2] 95 4e [2] 9a 54 [2] 84 49 [2] 86 48 [2] 9d 4e [2] 81 49 [2] 9d 66 }

  condition:
    any of them
}