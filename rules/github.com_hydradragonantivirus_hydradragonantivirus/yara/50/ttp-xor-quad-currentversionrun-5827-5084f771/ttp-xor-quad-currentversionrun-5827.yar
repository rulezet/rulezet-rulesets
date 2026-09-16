rule TTP_XOR_QUAD_CurrentVersionRun_5827 {
  strings:
    $key_5827 = { 0b 48 [2] 2f 46 [2] 04 6a [2] 2a 48 [2] 3e 53 [2] 31 49 [2] 2f 54 [2] 2d 55 [2] 36 53 [2] 2a 54 [2] 36 7b }

  condition:
    any of them
}