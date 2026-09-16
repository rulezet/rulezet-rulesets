rule TTP_XOR_QUAD_CurrentVersionRun_283e {
  strings:
    $key_283e = { 7b 51 [2] 5f 5f [2] 74 73 [2] 5a 51 [2] 4e 4a [2] 41 50 [2] 5f 4d [2] 5d 4c [2] 46 4a [2] 5a 4d [2] 46 62 }

  condition:
    any of them
}