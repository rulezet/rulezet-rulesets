rule TTP_XOR_QUAD_CurrentVersionRun_f06e {
  strings:
    $key_f06e = { a3 01 [2] 87 0f [2] ac 23 [2] 82 01 [2] 96 1a [2] 99 00 [2] 87 1d [2] 85 1c [2] 9e 1a [2] 82 1d [2] 9e 32 }

  condition:
    any of them
}