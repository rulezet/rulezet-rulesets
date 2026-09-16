rule TTP_XOR_QUAD_CurrentVersionRun_582b {
  strings:
    $key_582b = { 0b 44 [2] 2f 4a [2] 04 66 [2] 2a 44 [2] 3e 5f [2] 31 45 [2] 2f 58 [2] 2d 59 [2] 36 5f [2] 2a 58 [2] 36 77 }

  condition:
    any of them
}