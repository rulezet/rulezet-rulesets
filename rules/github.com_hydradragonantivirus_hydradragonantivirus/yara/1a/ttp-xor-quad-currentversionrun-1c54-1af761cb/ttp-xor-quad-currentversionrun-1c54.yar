rule TTP_XOR_QUAD_CurrentVersionRun_1c54 {
  strings:
    $key_1c54 = { 4f 3b [2] 6b 35 [2] 40 19 [2] 6e 3b [2] 7a 20 [2] 75 3a [2] 6b 27 [2] 69 26 [2] 72 20 [2] 6e 27 [2] 72 08 }

  condition:
    any of them
}