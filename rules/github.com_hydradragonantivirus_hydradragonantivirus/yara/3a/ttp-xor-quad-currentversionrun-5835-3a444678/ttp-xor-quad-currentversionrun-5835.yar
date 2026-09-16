rule TTP_XOR_QUAD_CurrentVersionRun_5835 {
  strings:
    $key_5835 = { 0b 5a [2] 2f 54 [2] 04 78 [2] 2a 5a [2] 3e 41 [2] 31 5b [2] 2f 46 [2] 2d 47 [2] 36 41 [2] 2a 46 [2] 36 69 }

  condition:
    any of them
}