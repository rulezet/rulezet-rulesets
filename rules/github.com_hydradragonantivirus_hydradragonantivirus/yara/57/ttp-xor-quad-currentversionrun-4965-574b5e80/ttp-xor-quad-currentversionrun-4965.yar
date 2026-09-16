rule TTP_XOR_QUAD_CurrentVersionRun_4965 {
  strings:
    $key_4965 = { 1a 0a [2] 3e 04 [2] 15 28 [2] 3b 0a [2] 2f 11 [2] 20 0b [2] 3e 16 [2] 3c 17 [2] 27 11 [2] 3b 16 [2] 27 39 }

  condition:
    any of them
}