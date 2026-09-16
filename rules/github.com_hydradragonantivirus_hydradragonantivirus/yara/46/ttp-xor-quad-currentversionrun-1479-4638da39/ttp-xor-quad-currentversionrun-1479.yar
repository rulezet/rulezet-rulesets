rule TTP_XOR_QUAD_CurrentVersionRun_1479 {
  strings:
    $key_1479 = { 47 16 [2] 63 18 [2] 48 34 [2] 66 16 [2] 72 0d [2] 7d 17 [2] 63 0a [2] 61 0b [2] 7a 0d [2] 66 0a [2] 7a 25 }

  condition:
    any of them
}