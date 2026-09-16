rule TTP_XOR_QUAD_CurrentVersionRun_2679 {
  strings:
    $key_2679 = { 75 16 [2] 51 18 [2] 7a 34 [2] 54 16 [2] 40 0d [2] 4f 17 [2] 51 0a [2] 53 0b [2] 48 0d [2] 54 0a [2] 48 25 }

  condition:
    any of them
}