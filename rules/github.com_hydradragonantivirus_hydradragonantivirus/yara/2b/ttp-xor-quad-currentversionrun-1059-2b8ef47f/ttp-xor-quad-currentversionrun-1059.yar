rule TTP_XOR_QUAD_CurrentVersionRun_1059 {
  strings:
    $key_1059 = { 43 36 [2] 67 38 [2] 4c 14 [2] 62 36 [2] 76 2d [2] 79 37 [2] 67 2a [2] 65 2b [2] 7e 2d [2] 62 2a [2] 7e 05 }

  condition:
    any of them
}