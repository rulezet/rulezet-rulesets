rule TTP_XOR_QUAD_CurrentVersionRun_6d4b {
  strings:
    $key_6d4b = { 3e 24 [2] 1a 2a [2] 31 06 [2] 1f 24 [2] 0b 3f [2] 04 25 [2] 1a 38 [2] 18 39 [2] 03 3f [2] 1f 38 [2] 03 17 }

  condition:
    any of them
}