rule TTP_XOR_QUAD_CurrentVersionRun_f42d {
  strings:
    $key_f42d = { a7 42 [2] 83 4c [2] a8 60 [2] 86 42 [2] 92 59 [2] 9d 43 [2] 83 5e [2] 81 5f [2] 9a 59 [2] 86 5e [2] 9a 71 }

  condition:
    any of them
}