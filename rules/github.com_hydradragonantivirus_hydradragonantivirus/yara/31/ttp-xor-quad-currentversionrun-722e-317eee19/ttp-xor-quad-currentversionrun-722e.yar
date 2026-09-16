rule TTP_XOR_QUAD_CurrentVersionRun_722e {
  strings:
    $key_722e = { 21 41 [2] 05 4f [2] 2e 63 [2] 00 41 [2] 14 5a [2] 1b 40 [2] 05 5d [2] 07 5c [2] 1c 5a [2] 00 5d [2] 1c 72 }

  condition:
    any of them
}