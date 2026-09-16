rule TTP_XOR_QUAD_CurrentVersionRun_786e {
  strings:
    $key_786e = { 2b 01 [2] 0f 0f [2] 24 23 [2] 0a 01 [2] 1e 1a [2] 11 00 [2] 0f 1d [2] 0d 1c [2] 16 1a [2] 0a 1d [2] 16 32 }

  condition:
    any of them
}