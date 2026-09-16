rule TTP_XOR_QUAD_CurrentVersionRun_f16e {
  strings:
    $key_f16e = { a2 01 [2] 86 0f [2] ad 23 [2] 83 01 [2] 97 1a [2] 98 00 [2] 86 1d [2] 84 1c [2] 9f 1a [2] 83 1d [2] 9f 32 }

  condition:
    any of them
}