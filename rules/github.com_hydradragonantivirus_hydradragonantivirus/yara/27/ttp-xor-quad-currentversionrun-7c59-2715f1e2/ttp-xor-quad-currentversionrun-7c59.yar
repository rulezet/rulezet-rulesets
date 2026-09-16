rule TTP_XOR_QUAD_CurrentVersionRun_7c59 {
  strings:
    $key_7c59 = { 2f 36 [2] 0b 38 [2] 20 14 [2] 0e 36 [2] 1a 2d [2] 15 37 [2] 0b 2a [2] 09 2b [2] 12 2d [2] 0e 2a [2] 12 05 }

  condition:
    any of them
}