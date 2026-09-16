rule TTP_XOR_QUAD_CurrentVersionRun_6264 {
  strings:
    $key_6264 = { 31 0b [2] 15 05 [2] 3e 29 [2] 10 0b [2] 04 10 [2] 0b 0a [2] 15 17 [2] 17 16 [2] 0c 10 [2] 10 17 [2] 0c 38 }

  condition:
    any of them
}