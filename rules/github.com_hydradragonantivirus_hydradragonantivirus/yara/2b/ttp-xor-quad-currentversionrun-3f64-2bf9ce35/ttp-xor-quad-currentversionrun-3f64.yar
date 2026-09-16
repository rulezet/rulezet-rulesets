rule TTP_XOR_QUAD_CurrentVersionRun_3f64 {
  strings:
    $key_3f64 = { 6c 0b [2] 48 05 [2] 63 29 [2] 4d 0b [2] 59 10 [2] 56 0a [2] 48 17 [2] 4a 16 [2] 51 10 [2] 4d 17 [2] 51 38 }

  condition:
    any of them
}