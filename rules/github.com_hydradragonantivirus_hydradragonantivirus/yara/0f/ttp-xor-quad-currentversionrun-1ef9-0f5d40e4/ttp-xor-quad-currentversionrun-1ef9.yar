rule TTP_XOR_QUAD_CurrentVersionRun_1ef9 {
  strings:
    $key_1ef9 = { 4d 96 [2] 69 98 [2] 42 b4 [2] 6c 96 [2] 78 8d [2] 77 97 [2] 69 8a [2] 6b 8b [2] 70 8d [2] 6c 8a [2] 70 a5 }

  condition:
    any of them
}