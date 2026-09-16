rule TTP_XOR_QUAD_CurrentVersionRun_0ef9 {
  strings:
    $key_0ef9 = { 5d 96 [2] 79 98 [2] 52 b4 [2] 7c 96 [2] 68 8d [2] 67 97 [2] 79 8a [2] 7b 8b [2] 60 8d [2] 7c 8a [2] 60 a5 }

  condition:
    any of them
}