rule TTP_XOR_QUAD_CurrentVersionRun_6d27 {
  strings:
    $key_6d27 = { 3e 48 [2] 1a 46 [2] 31 6a [2] 1f 48 [2] 0b 53 [2] 04 49 [2] 1a 54 [2] 18 55 [2] 03 53 [2] 1f 54 [2] 03 7b }

  condition:
    any of them
}