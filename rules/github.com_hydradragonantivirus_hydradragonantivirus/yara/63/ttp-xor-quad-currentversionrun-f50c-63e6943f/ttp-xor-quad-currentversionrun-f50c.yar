rule TTP_XOR_QUAD_CurrentVersionRun_f50c {
  strings:
    $key_f50c = { a6 63 [2] 82 6d [2] a9 41 [2] 87 63 [2] 93 78 [2] 9c 62 [2] 82 7f [2] 80 7e [2] 9b 78 [2] 87 7f [2] 9b 50 }

  condition:
    any of them
}