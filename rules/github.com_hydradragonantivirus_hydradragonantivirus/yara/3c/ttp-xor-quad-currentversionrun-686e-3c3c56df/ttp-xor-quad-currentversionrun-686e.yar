rule TTP_XOR_QUAD_CurrentVersionRun_686e {
  strings:
    $key_686e = { 3b 01 [2] 1f 0f [2] 34 23 [2] 1a 01 [2] 0e 1a [2] 01 00 [2] 1f 1d [2] 1d 1c [2] 06 1a [2] 1a 1d [2] 06 32 }

  condition:
    any of them
}