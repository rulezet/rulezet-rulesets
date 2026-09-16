rule TTP_XOR_QUAD_CurrentVersionRun_6d39 {
  strings:
    $key_6d39 = { 3e 56 [2] 1a 58 [2] 31 74 [2] 1f 56 [2] 0b 4d [2] 04 57 [2] 1a 4a [2] 18 4b [2] 03 4d [2] 1f 4a [2] 03 65 }

  condition:
    any of them
}