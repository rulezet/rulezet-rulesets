rule TTP_XOR_QUAD_CurrentVersionRun_286e {
  strings:
    $key_286e = { 7b 01 [2] 5f 0f [2] 74 23 [2] 5a 01 [2] 4e 1a [2] 41 00 [2] 5f 1d [2] 5d 1c [2] 46 1a [2] 5a 1d [2] 46 32 }

  condition:
    any of them
}