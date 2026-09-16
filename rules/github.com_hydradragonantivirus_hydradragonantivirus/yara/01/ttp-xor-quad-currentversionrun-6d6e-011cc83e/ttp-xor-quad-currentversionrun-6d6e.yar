rule TTP_XOR_QUAD_CurrentVersionRun_6d6e {
  strings:
    $key_6d6e = { 3e 01 [2] 1a 0f [2] 31 23 [2] 1f 01 [2] 0b 1a [2] 04 00 [2] 1a 1d [2] 18 1c [2] 03 1a [2] 1f 1d [2] 03 32 }

  condition:
    any of them
}