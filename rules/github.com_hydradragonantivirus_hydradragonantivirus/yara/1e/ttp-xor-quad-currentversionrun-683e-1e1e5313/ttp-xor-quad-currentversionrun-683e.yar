rule TTP_XOR_QUAD_CurrentVersionRun_683e {
  strings:
    $key_683e = { 3b 51 [2] 1f 5f [2] 34 73 [2] 1a 51 [2] 0e 4a [2] 01 50 [2] 1f 4d [2] 1d 4c [2] 06 4a [2] 1a 4d [2] 06 62 }

  condition:
    any of them
}