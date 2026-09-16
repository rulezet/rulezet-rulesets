rule TTP_XOR_QUAD_CurrentVersionRun_6d44 {
  strings:
    $key_6d44 = { 3e 2b [2] 1a 25 [2] 31 09 [2] 1f 2b [2] 0b 30 [2] 04 2a [2] 1a 37 [2] 18 36 [2] 03 30 [2] 1f 37 [2] 03 18 }

  condition:
    any of them
}