rule TTP_XOR_QUAD_CurrentVersionRun_fa3a {
  strings:
    $key_fa3a = { a9 55 [2] 8d 5b [2] a6 77 [2] 88 55 [2] 9c 4e [2] 93 54 [2] 8d 49 [2] 8f 48 [2] 94 4e [2] 88 49 [2] 94 66 }

  condition:
    any of them
}