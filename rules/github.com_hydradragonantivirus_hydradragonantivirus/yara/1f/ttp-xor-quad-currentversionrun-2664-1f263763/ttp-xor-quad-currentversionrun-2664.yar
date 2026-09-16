rule TTP_XOR_QUAD_CurrentVersionRun_2664 {
  strings:
    $key_2664 = { 75 0b [2] 51 05 [2] 7a 29 [2] 54 0b [2] 40 10 [2] 4f 0a [2] 51 17 [2] 53 16 [2] 48 10 [2] 54 17 [2] 48 38 }

  condition:
    any of them
}