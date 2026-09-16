rule TTP_XOR_QUAD_CurrentVersionRun_f552 {
  strings:
    $key_f552 = { a6 3d [2] 82 33 [2] a9 1f [2] 87 3d [2] 93 26 [2] 9c 3c [2] 82 21 [2] 80 20 [2] 9b 26 [2] 87 21 [2] 9b 0e }

  condition:
    any of them
}