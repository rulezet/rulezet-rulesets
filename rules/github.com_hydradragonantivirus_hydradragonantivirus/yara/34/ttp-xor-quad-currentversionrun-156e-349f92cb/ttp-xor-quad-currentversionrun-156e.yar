rule TTP_XOR_QUAD_CurrentVersionRun_156e {
  strings:
    $key_156e = { 46 01 [2] 62 0f [2] 49 23 [2] 67 01 [2] 73 1a [2] 7c 00 [2] 62 1d [2] 60 1c [2] 7b 1a [2] 67 1d [2] 7b 32 }

  condition:
    any of them
}