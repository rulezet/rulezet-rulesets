rule TTP_XOR_QUAD_CurrentVersionRun_3764 {
  strings:
    $key_3764 = { 64 0b [2] 40 05 [2] 6b 29 [2] 45 0b [2] 51 10 [2] 5e 0a [2] 40 17 [2] 42 16 [2] 59 10 [2] 45 17 [2] 59 38 }

  condition:
    any of them
}