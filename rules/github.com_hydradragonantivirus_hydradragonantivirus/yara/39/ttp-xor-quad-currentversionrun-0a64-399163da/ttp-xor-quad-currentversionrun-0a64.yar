rule TTP_XOR_QUAD_CurrentVersionRun_0a64 {
  strings:
    $key_0a64 = { 59 0b [2] 7d 05 [2] 56 29 [2] 78 0b [2] 6c 10 [2] 63 0a [2] 7d 17 [2] 7f 16 [2] 64 10 [2] 78 17 [2] 64 38 }

  condition:
    any of them
}