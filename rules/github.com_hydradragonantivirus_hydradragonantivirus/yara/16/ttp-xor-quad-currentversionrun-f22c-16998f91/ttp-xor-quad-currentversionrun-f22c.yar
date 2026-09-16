rule TTP_XOR_QUAD_CurrentVersionRun_f22c {
  strings:
    $key_f22c = { a1 43 [2] 85 4d [2] ae 61 [2] 80 43 [2] 94 58 [2] 9b 42 [2] 85 5f [2] 87 5e [2] 9c 58 [2] 80 5f [2] 9c 70 }

  condition:
    any of them
}