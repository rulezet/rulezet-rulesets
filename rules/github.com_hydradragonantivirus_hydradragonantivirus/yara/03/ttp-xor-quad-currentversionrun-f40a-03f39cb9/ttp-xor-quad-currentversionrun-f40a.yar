rule TTP_XOR_QUAD_CurrentVersionRun_f40a {
  strings:
    $key_f40a = { a7 65 [2] 83 6b [2] a8 47 [2] 86 65 [2] 92 7e [2] 9d 64 [2] 83 79 [2] 81 78 [2] 9a 7e [2] 86 79 [2] 9a 56 }

  condition:
    any of them
}