rule TTP_XOR_QUAD_CurrentVersionRun_0d64 {
  strings:
    $key_0d64 = { 5e 0b [2] 7a 05 [2] 51 29 [2] 7f 0b [2] 6b 10 [2] 64 0a [2] 7a 17 [2] 78 16 [2] 63 10 [2] 7f 17 [2] 63 38 }

  condition:
    any of them
}