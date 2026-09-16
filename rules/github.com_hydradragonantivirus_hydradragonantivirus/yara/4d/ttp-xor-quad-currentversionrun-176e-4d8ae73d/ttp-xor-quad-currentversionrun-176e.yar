rule TTP_XOR_QUAD_CurrentVersionRun_176e {
  strings:
    $key_176e = { 44 01 [2] 60 0f [2] 4b 23 [2] 65 01 [2] 71 1a [2] 7e 00 [2] 60 1d [2] 62 1c [2] 79 1a [2] 65 1d [2] 79 32 }

  condition:
    any of them
}