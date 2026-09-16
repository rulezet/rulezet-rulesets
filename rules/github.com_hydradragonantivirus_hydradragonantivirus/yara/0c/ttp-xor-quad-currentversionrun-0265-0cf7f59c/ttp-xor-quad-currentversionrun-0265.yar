rule TTP_XOR_QUAD_CurrentVersionRun_0265 {
  strings:
    $key_0265 = { 51 0a [2] 75 04 [2] 5e 28 [2] 70 0a [2] 64 11 [2] 6b 0b [2] 75 16 [2] 77 17 [2] 6c 11 [2] 70 16 [2] 6c 39 }

  condition:
    any of them
}