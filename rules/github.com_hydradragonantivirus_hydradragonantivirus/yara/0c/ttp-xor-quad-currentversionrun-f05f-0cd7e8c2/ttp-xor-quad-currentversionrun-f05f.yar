rule TTP_XOR_QUAD_CurrentVersionRun_f05f {
  strings:
    $key_f05f = { a3 30 [2] 87 3e [2] ac 12 [2] 82 30 [2] 96 2b [2] 99 31 [2] 87 2c [2] 85 2d [2] 9e 2b [2] 82 2c [2] 9e 03 }

  condition:
    any of them
}