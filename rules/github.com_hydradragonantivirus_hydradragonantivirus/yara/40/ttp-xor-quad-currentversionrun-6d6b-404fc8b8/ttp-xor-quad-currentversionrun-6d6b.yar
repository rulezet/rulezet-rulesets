rule TTP_XOR_QUAD_CurrentVersionRun_6d6b {
  strings:
    $key_6d6b = { 3e 04 [2] 1a 0a [2] 31 26 [2] 1f 04 [2] 0b 1f [2] 04 05 [2] 1a 18 [2] 18 19 [2] 03 1f [2] 1f 18 [2] 03 37 }

  condition:
    any of them
}