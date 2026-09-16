rule TTP_XOR_QUAD_CurrentVersionRun_f43a {
  strings:
    $key_f43a = { a7 55 [2] 83 5b [2] a8 77 [2] 86 55 [2] 92 4e [2] 9d 54 [2] 83 49 [2] 81 48 [2] 9a 4e [2] 86 49 [2] 9a 66 }

  condition:
    any of them
}