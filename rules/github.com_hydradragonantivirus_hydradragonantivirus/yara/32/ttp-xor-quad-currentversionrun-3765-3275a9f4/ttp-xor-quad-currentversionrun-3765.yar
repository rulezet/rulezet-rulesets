rule TTP_XOR_QUAD_CurrentVersionRun_3765 {
  strings:
    $key_3765 = { 64 0a [2] 40 04 [2] 6b 28 [2] 45 0a [2] 51 11 [2] 5e 0b [2] 40 16 [2] 42 17 [2] 59 11 [2] 45 16 [2] 59 39 }

  condition:
    any of them
}