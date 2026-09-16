rule TTP_XOR_QUAD_CurrentVersionRun_7c78 {
  strings:
    $key_7c78 = { 2f 17 [2] 0b 19 [2] 20 35 [2] 0e 17 [2] 1a 0c [2] 15 16 [2] 0b 0b [2] 09 0a [2] 12 0c [2] 0e 0b [2] 12 24 }

  condition:
    any of them
}