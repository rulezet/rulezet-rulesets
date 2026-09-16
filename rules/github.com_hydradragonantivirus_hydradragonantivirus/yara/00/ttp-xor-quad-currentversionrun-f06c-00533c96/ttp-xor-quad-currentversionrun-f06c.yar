rule TTP_XOR_QUAD_CurrentVersionRun_f06c {
  strings:
    $key_f06c = { a3 03 [2] 87 0d [2] ac 21 [2] 82 03 [2] 96 18 [2] 99 02 [2] 87 1f [2] 85 1e [2] 9e 18 [2] 82 1f [2] 9e 30 }

  condition:
    any of them
}