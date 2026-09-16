rule TTP_XOR_QUAD_CurrentVersionRun_5865 {
  strings:
    $key_5865 = { 0b 0a [2] 2f 04 [2] 04 28 [2] 2a 0a [2] 3e 11 [2] 31 0b [2] 2f 16 [2] 2d 17 [2] 36 11 [2] 2a 16 [2] 36 39 }

  condition:
    any of them
}