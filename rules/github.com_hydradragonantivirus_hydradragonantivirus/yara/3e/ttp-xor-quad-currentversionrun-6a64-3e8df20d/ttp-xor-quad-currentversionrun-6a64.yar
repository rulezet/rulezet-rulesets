rule TTP_XOR_QUAD_CurrentVersionRun_6a64 {
  strings:
    $key_6a64 = { 39 0b [2] 1d 05 [2] 36 29 [2] 18 0b [2] 0c 10 [2] 03 0a [2] 1d 17 [2] 1f 16 [2] 04 10 [2] 18 17 [2] 04 38 }

  condition:
    any of them
}