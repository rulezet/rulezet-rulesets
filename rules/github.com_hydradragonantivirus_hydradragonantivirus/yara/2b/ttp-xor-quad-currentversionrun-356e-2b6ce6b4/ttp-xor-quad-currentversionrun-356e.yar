rule TTP_XOR_QUAD_CurrentVersionRun_356e {
  strings:
    $key_356e = { 66 01 [2] 42 0f [2] 69 23 [2] 47 01 [2] 53 1a [2] 5c 00 [2] 42 1d [2] 40 1c [2] 5b 1a [2] 47 1d [2] 5b 32 }

  condition:
    any of them
}