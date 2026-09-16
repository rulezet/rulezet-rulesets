rule TTP_XOR_QUAD_CurrentVersionRun_5f64 {
  strings:
    $key_5f64 = { 0c 0b [2] 28 05 [2] 03 29 [2] 2d 0b [2] 39 10 [2] 36 0a [2] 28 17 [2] 2a 16 [2] 31 10 [2] 2d 17 [2] 31 38 }

  condition:
    any of them
}