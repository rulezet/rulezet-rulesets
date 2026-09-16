rule TTP_XOR_QUAD_CurrentVersionRun_f01c {
  strings:
    $key_f01c = { a3 73 [2] 87 7d [2] ac 51 [2] 82 73 [2] 96 68 [2] 99 72 [2] 87 6f [2] 85 6e [2] 9e 68 [2] 82 6f [2] 9e 40 }

  condition:
    any of them
}