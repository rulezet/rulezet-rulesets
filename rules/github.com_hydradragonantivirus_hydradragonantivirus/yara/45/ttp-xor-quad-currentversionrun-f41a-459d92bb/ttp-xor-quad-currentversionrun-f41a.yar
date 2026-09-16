rule TTP_XOR_QUAD_CurrentVersionRun_f41a {
  strings:
    $key_f41a = { a7 75 [2] 83 7b [2] a8 57 [2] 86 75 [2] 92 6e [2] 9d 74 [2] 83 69 [2] 81 68 [2] 9a 6e [2] 86 69 [2] 9a 46 }

  condition:
    any of them
}