rule TTP_XOR_QUAD_CurrentVersionRun_7bf9 {
  strings:
    $key_7bf9 = { 28 96 [2] 0c 98 [2] 27 b4 [2] 09 96 [2] 1d 8d [2] 12 97 [2] 0c 8a [2] 0e 8b [2] 15 8d [2] 09 8a [2] 15 a5 }

  condition:
    any of them
}