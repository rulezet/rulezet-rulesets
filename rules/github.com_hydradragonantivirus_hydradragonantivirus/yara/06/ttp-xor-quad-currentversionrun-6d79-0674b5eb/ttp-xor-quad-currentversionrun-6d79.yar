rule TTP_XOR_QUAD_CurrentVersionRun_6d79 {
  strings:
    $key_6d79 = { 3e 16 [2] 1a 18 [2] 31 34 [2] 1f 16 [2] 0b 0d [2] 04 17 [2] 1a 0a [2] 18 0b [2] 03 0d [2] 1f 0a [2] 03 25 }

  condition:
    any of them
}