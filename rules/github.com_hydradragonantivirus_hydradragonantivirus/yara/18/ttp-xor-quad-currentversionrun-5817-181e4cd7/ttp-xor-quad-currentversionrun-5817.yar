rule TTP_XOR_QUAD_CurrentVersionRun_5817 {
  strings:
    $key_5817 = { 0b 78 [2] 2f 76 [2] 04 5a [2] 2a 78 [2] 3e 63 [2] 31 79 [2] 2f 64 [2] 2d 65 [2] 36 63 [2] 2a 64 [2] 36 4b }

  condition:
    any of them
}