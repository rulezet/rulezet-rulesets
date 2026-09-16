rule TTP_XOR_QUAD_CurrentVersionRun_f434 {
  strings:
    $key_f434 = { a7 5b [2] 83 55 [2] a8 79 [2] 86 5b [2] 92 40 [2] 9d 5a [2] 83 47 [2] 81 46 [2] 9a 40 [2] 86 47 [2] 9a 68 }

  condition:
    any of them
}