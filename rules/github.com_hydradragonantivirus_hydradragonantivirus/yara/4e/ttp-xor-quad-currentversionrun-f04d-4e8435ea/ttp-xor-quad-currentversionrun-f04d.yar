rule TTP_XOR_QUAD_CurrentVersionRun_f04d {
  strings:
    $key_f04d = { a3 22 [2] 87 2c [2] ac 00 [2] 82 22 [2] 96 39 [2] 99 23 [2] 87 3e [2] 85 3f [2] 9e 39 [2] 82 3e [2] 9e 11 }

  condition:
    any of them
}