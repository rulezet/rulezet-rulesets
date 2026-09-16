rule TTP_XOR_QUAD_CurrentVersionRun_406e {
  strings:
    $key_406e = { 13 01 [2] 37 0f [2] 1c 23 [2] 32 01 [2] 26 1a [2] 29 00 [2] 37 1d [2] 35 1c [2] 2e 1a [2] 32 1d [2] 2e 32 }

  condition:
    any of them
}