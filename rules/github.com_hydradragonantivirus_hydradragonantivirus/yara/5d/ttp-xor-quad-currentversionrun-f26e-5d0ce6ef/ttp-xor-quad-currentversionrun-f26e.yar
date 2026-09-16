rule TTP_XOR_QUAD_CurrentVersionRun_f26e {
  strings:
    $key_f26e = { a1 01 [2] 85 0f [2] ae 23 [2] 80 01 [2] 94 1a [2] 9b 00 [2] 85 1d [2] 87 1c [2] 9c 1a [2] 80 1d [2] 9c 32 }

  condition:
    any of them
}