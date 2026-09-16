rule TTP_XOR_QUAD_CurrentVersionRun_316e {
  strings:
    $key_316e = { 62 01 [2] 46 0f [2] 6d 23 [2] 43 01 [2] 57 1a [2] 58 00 [2] 46 1d [2] 44 1c [2] 5f 1a [2] 43 1d [2] 5f 32 }

  condition:
    any of them
}