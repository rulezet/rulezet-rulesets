rule TTP_XOR_QUAD_CurrentVersionRun_6a79 {
  strings:
    $key_6a79 = { 39 16 [2] 1d 18 [2] 36 34 [2] 18 16 [2] 0c 0d [2] 03 17 [2] 1d 0a [2] 1f 0b [2] 04 0d [2] 18 0a [2] 04 25 }

  condition:
    any of them
}