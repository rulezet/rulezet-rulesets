rule TTP_XOR_QUAD_CurrentVersionRun_7cf9 {
  strings:
    $key_7cf9 = { 2f 96 [2] 0b 98 [2] 20 b4 [2] 0e 96 [2] 1a 8d [2] 15 97 [2] 0b 8a [2] 09 8b [2] 12 8d [2] 0e 8a [2] 12 a5 }

  condition:
    any of them
}