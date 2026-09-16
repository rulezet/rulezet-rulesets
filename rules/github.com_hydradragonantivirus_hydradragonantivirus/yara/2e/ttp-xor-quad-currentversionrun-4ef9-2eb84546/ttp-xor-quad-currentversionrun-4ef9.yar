rule TTP_XOR_QUAD_CurrentVersionRun_4ef9 {
  strings:
    $key_4ef9 = { 1d 96 [2] 39 98 [2] 12 b4 [2] 3c 96 [2] 28 8d [2] 27 97 [2] 39 8a [2] 3b 8b [2] 20 8d [2] 3c 8a [2] 20 a5 }

  condition:
    any of them
}