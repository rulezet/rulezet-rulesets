rule TTP_XOR_QUAD_CurrentVersionRun_633e {
  strings:
    $key_633e = { 30 51 [2] 14 5f [2] 3f 73 [2] 11 51 [2] 05 4a [2] 0a 50 [2] 14 4d [2] 16 4c [2] 0d 4a [2] 11 4d [2] 0d 62 }

  condition:
    any of them
}