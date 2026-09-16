rule TTP_XOR_QUAD_CurrentVersionRun_702e {
  strings:
    $key_702e = { 23 41 [2] 07 4f [2] 2c 63 [2] 02 41 [2] 16 5a [2] 19 40 [2] 07 5d [2] 05 5c [2] 1e 5a [2] 02 5d [2] 1e 72 }

  condition:
    any of them
}