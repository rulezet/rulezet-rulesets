rule TTP_XOR_QUAD_CurrentVersionRun_7ef9 {
  strings:
    $key_7ef9 = { 2d 96 [2] 09 98 [2] 22 b4 [2] 0c 96 [2] 18 8d [2] 17 97 [2] 09 8a [2] 0b 8b [2] 10 8d [2] 0c 8a [2] 10 a5 }

  condition:
    any of them
}