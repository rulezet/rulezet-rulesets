rule TTP_XOR_QUAD_CurrentVersionRun_2164 {
  strings:
    $key_2164 = { 72 0b [2] 56 05 [2] 7d 29 [2] 53 0b [2] 47 10 [2] 48 0a [2] 56 17 [2] 54 16 [2] 4f 10 [2] 53 17 [2] 4f 38 }

  condition:
    any of them
}