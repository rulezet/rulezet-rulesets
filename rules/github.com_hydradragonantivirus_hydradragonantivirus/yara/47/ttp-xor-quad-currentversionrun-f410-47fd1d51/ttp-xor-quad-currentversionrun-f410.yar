rule TTP_XOR_QUAD_CurrentVersionRun_f410 {
  strings:
    $key_f410 = { a7 7f [2] 83 71 [2] a8 5d [2] 86 7f [2] 92 64 [2] 9d 7e [2] 83 63 [2] 81 62 [2] 9a 64 [2] 86 63 [2] 9a 4c }

  condition:
    any of them
}