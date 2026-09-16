rule TTP_XOR_QUAD_CurrentVersionRun_6345 {
  strings:
    $key_6345 = { 30 2a [2] 14 24 [2] 3f 08 [2] 11 2a [2] 05 31 [2] 0a 2b [2] 14 36 [2] 16 37 [2] 0d 31 [2] 11 36 [2] 0d 19 }

  condition:
    any of them
}