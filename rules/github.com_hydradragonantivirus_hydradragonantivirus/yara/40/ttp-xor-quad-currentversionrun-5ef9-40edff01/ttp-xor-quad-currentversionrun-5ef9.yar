rule TTP_XOR_QUAD_CurrentVersionRun_5ef9 {
  strings:
    $key_5ef9 = { 0d 96 [2] 29 98 [2] 02 b4 [2] 2c 96 [2] 38 8d [2] 37 97 [2] 29 8a [2] 2b 8b [2] 30 8d [2] 2c 8a [2] 30 a5 }

  condition:
    any of them
}