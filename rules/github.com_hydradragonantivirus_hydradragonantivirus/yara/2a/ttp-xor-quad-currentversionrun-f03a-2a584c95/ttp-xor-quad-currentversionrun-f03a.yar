rule TTP_XOR_QUAD_CurrentVersionRun_f03a {
  strings:
    $key_f03a = { a3 55 [2] 87 5b [2] ac 77 [2] 82 55 [2] 96 4e [2] 99 54 [2] 87 49 [2] 85 48 [2] 9e 4e [2] 82 49 [2] 9e 66 }

  condition:
    any of them
}