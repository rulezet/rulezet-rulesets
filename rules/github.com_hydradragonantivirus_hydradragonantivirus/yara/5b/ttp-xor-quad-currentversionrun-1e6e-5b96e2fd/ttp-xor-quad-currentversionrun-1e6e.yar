rule TTP_XOR_QUAD_CurrentVersionRun_1e6e {
  strings:
    $key_1e6e = { 4d 01 [2] 69 0f [2] 42 23 [2] 6c 01 [2] 78 1a [2] 77 00 [2] 69 1d [2] 6b 1c [2] 70 1a [2] 6c 1d [2] 70 32 }

  condition:
    any of them
}