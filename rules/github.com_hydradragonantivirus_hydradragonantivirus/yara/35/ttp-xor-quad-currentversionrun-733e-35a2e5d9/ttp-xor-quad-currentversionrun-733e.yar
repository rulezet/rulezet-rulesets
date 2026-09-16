rule TTP_XOR_QUAD_CurrentVersionRun_733e {
  strings:
    $key_733e = { 20 51 [2] 04 5f [2] 2f 73 [2] 01 51 [2] 15 4a [2] 1a 50 [2] 04 4d [2] 06 4c [2] 1d 4a [2] 01 4d [2] 1d 62 }

  condition:
    any of them
}