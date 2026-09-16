rule TTP_XOR_QUAD_CurrentVersionRun_f76e {
  strings:
    $key_f76e = { a4 01 [2] 80 0f [2] ab 23 [2] 85 01 [2] 91 1a [2] 9e 00 [2] 80 1d [2] 82 1c [2] 99 1a [2] 85 1d [2] 99 32 }

  condition:
    any of them
}