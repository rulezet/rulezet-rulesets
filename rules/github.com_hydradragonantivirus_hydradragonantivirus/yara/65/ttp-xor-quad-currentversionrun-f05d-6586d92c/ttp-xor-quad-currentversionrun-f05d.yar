rule TTP_XOR_QUAD_CurrentVersionRun_f05d {
  strings:
    $key_f05d = { a3 32 [2] 87 3c [2] ac 10 [2] 82 32 [2] 96 29 [2] 99 33 [2] 87 2e [2] 85 2f [2] 9e 29 [2] 82 2e [2] 9e 01 }

  condition:
    any of them
}