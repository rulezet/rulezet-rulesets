rule TTP_XOR_QUAD_CurrentVersionRun_2165 {
  strings:
    $key_2165 = { 72 0a [2] 56 04 [2] 7d 28 [2] 53 0a [2] 47 11 [2] 48 0b [2] 56 16 [2] 54 17 [2] 4f 11 [2] 53 16 [2] 4f 39 }

  condition:
    any of them
}