rule TTP_XOR_QUAD_CurrentVersionRun_583b {
  strings:
    $key_583b = { 0b 54 [2] 2f 5a [2] 04 76 [2] 2a 54 [2] 3e 4f [2] 31 55 [2] 2f 48 [2] 2d 49 [2] 36 4f [2] 2a 48 [2] 36 67 }

  condition:
    any of them
}