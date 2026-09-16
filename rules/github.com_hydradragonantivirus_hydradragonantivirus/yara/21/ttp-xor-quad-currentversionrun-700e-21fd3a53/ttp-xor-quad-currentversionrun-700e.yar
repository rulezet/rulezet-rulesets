rule TTP_XOR_QUAD_CurrentVersionRun_700e {
  strings:
    $key_700e = { 23 61 [2] 07 6f [2] 2c 43 [2] 02 61 [2] 16 7a [2] 19 60 [2] 07 7d [2] 05 7c [2] 1e 7a [2] 02 7d [2] 1e 52 }

  condition:
    any of them
}