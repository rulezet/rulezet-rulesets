rule TTP_XOR_QUAD_CurrentVersionRun_2b6e {
  strings:
    $key_2b6e = { 78 01 [2] 5c 0f [2] 77 23 [2] 59 01 [2] 4d 1a [2] 42 00 [2] 5c 1d [2] 5e 1c [2] 45 1a [2] 59 1d [2] 45 32 }

  condition:
    any of them
}