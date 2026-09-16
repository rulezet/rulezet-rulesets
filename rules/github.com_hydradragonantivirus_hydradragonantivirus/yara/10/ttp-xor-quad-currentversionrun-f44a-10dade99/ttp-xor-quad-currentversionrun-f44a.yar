rule TTP_XOR_QUAD_CurrentVersionRun_f44a {
  strings:
    $key_f44a = { a7 25 [2] 83 2b [2] a8 07 [2] 86 25 [2] 92 3e [2] 9d 24 [2] 83 39 [2] 81 38 [2] 9a 3e [2] 86 39 [2] 9a 16 }

  condition:
    any of them
}