rule TTP_XOR_QUAD_CurrentVersionRun_6019 {
  strings:
    $key_6019 = { 33 76 [2] 17 78 [2] 3c 54 [2] 12 76 [2] 06 6d [2] 09 77 [2] 17 6a [2] 15 6b [2] 0e 6d [2] 12 6a [2] 0e 45 }

  condition:
    any of them
}