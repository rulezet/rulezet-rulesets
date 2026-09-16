rule TTP_XOR_QUAD_CurrentVersionRun_f40c {
  strings:
    $key_f40c = { a7 63 [2] 83 6d [2] a8 41 [2] 86 63 [2] 92 78 [2] 9d 62 [2] 83 7f [2] 81 7e [2] 9a 78 [2] 86 7f [2] 9a 50 }

  condition:
    any of them
}