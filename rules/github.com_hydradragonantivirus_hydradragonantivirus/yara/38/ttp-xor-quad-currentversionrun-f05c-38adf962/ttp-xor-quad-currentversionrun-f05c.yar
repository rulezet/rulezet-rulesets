rule TTP_XOR_QUAD_CurrentVersionRun_f05c {
  strings:
    $key_f05c = { a3 33 [2] 87 3d [2] ac 11 [2] 82 33 [2] 96 28 [2] 99 32 [2] 87 2f [2] 85 2e [2] 9e 28 [2] 82 2f [2] 9e 00 }

  condition:
    any of them
}