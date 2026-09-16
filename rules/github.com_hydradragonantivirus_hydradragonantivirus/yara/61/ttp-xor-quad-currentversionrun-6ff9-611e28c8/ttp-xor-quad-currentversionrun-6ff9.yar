rule TTP_XOR_QUAD_CurrentVersionRun_6ff9 {
  strings:
    $key_6ff9 = { 3c 96 [2] 18 98 [2] 33 b4 [2] 1d 96 [2] 09 8d [2] 06 97 [2] 18 8a [2] 1a 8b [2] 01 8d [2] 1d 8a [2] 01 a5 }

  condition:
    any of them
}