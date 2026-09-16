rule TTP_XOR_QUAD_CurrentVersionRun_7773 {
  strings:
    $key_7773 = { 24 1c [2] 00 12 [2] 2b 3e [2] 05 1c [2] 11 07 [2] 1e 1d [2] 00 00 [2] 02 01 [2] 19 07 [2] 05 00 [2] 19 2f }

  condition:
    any of them
}