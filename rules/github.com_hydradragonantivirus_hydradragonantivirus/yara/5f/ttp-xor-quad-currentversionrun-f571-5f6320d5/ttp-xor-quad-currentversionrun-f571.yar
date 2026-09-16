rule TTP_XOR_QUAD_CurrentVersionRun_f571 {
  strings:
    $key_f571 = { a6 1e [2] 82 10 [2] a9 3c [2] 87 1e [2] 93 05 [2] 9c 1f [2] 82 02 [2] 80 03 [2] 9b 05 [2] 87 02 [2] 9b 2d }

  condition:
    any of them
}