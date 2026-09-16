rule TTP_XOR_QUAD_CurrentVersionRun_6529 {
  strings:
    $key_6529 = { 36 46 [2] 12 48 [2] 39 64 [2] 17 46 [2] 03 5d [2] 0c 47 [2] 12 5a [2] 10 5b [2] 0b 5d [2] 17 5a [2] 0b 75 }

  condition:
    any of them
}