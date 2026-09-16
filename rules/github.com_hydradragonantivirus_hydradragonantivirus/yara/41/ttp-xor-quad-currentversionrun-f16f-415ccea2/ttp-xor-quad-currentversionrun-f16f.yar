rule TTP_XOR_QUAD_CurrentVersionRun_f16f {
  strings:
    $key_f16f = { a2 00 [2] 86 0e [2] ad 22 [2] 83 00 [2] 97 1b [2] 98 01 [2] 86 1c [2] 84 1d [2] 9f 1b [2] 83 1c [2] 9f 33 }

  condition:
    any of them
}