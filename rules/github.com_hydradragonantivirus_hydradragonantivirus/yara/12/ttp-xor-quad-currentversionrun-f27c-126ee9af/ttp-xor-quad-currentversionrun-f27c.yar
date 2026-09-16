rule TTP_XOR_QUAD_CurrentVersionRun_f27c {
  strings:
    $key_f27c = { a1 13 [2] 85 1d [2] ae 31 [2] 80 13 [2] 94 08 [2] 9b 12 [2] 85 0f [2] 87 0e [2] 9c 08 [2] 80 0f [2] 9c 20 }

  condition:
    any of them
}