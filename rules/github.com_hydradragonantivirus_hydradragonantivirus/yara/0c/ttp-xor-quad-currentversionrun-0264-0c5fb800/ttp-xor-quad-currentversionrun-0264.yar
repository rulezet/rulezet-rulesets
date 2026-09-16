rule TTP_XOR_QUAD_CurrentVersionRun_0264 {
  strings:
    $key_0264 = { 51 0b [2] 75 05 [2] 5e 29 [2] 70 0b [2] 64 10 [2] 6b 0a [2] 75 17 [2] 77 16 [2] 6c 10 [2] 70 17 [2] 6c 38 }

  condition:
    any of them
}