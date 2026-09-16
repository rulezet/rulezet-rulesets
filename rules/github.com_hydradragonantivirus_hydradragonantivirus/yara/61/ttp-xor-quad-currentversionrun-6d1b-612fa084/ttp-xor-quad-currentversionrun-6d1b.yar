rule TTP_XOR_QUAD_CurrentVersionRun_6d1b {
  strings:
    $key_6d1b = { 3e 74 [2] 1a 7a [2] 31 56 [2] 1f 74 [2] 0b 6f [2] 04 75 [2] 1a 68 [2] 18 69 [2] 03 6f [2] 1f 68 [2] 03 47 }

  condition:
    any of them
}