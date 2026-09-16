rule TTP_XOR_QUAD_CurrentVersionRun_1e54 {
  strings:
    $key_1e54 = { 4d 3b [2] 69 35 [2] 42 19 [2] 6c 3b [2] 78 20 [2] 77 3a [2] 69 27 [2] 6b 26 [2] 70 20 [2] 6c 27 [2] 70 08 }

  condition:
    any of them
}