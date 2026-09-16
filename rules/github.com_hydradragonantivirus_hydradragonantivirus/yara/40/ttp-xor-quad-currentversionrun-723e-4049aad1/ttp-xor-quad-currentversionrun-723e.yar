rule TTP_XOR_QUAD_CurrentVersionRun_723e {
  strings:
    $key_723e = { 21 51 [2] 05 5f [2] 2e 73 [2] 00 51 [2] 14 4a [2] 1b 50 [2] 05 4d [2] 07 4c [2] 1c 4a [2] 00 4d [2] 1c 62 }

  condition:
    any of them
}