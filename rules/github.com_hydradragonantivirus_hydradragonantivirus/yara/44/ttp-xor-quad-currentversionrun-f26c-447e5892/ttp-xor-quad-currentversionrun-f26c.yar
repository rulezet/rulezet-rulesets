rule TTP_XOR_QUAD_CurrentVersionRun_f26c {
  strings:
    $key_f26c = { a1 03 [2] 85 0d [2] ae 21 [2] 80 03 [2] 94 18 [2] 9b 02 [2] 85 1f [2] 87 1e [2] 9c 18 [2] 80 1f [2] 9c 30 }

  condition:
    any of them
}