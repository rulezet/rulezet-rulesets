rule TTP_XOR_QUAD_CurrentVersionRun_696e {
  strings:
    $key_696e = { 3a 01 [2] 1e 0f [2] 35 23 [2] 1b 01 [2] 0f 1a [2] 00 00 [2] 1e 1d [2] 1c 1c [2] 07 1a [2] 1b 1d [2] 07 32 }

  condition:
    any of them
}