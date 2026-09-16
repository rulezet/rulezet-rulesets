rule TTP_XOR_QUAD_CurrentVersionRun_7c54 {
  strings:
    $key_7c54 = { 2f 3b [2] 0b 35 [2] 20 19 [2] 0e 3b [2] 1a 20 [2] 15 3a [2] 0b 27 [2] 09 26 [2] 12 20 [2] 0e 27 [2] 12 08 }

  condition:
    any of them
}