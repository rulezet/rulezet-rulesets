rule TTP_XOR_QUAD_CurrentVersionRun_f73a {
  strings:
    $key_f73a = { a4 55 [2] 80 5b [2] ab 77 [2] 85 55 [2] 91 4e [2] 9e 54 [2] 80 49 [2] 82 48 [2] 99 4e [2] 85 49 [2] 99 66 }

  condition:
    any of them
}