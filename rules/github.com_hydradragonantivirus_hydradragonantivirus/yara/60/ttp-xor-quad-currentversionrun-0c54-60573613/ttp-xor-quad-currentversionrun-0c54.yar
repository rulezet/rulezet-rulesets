rule TTP_XOR_QUAD_CurrentVersionRun_0c54 {
  strings:
    $key_0c54 = { 5f 3b [2] 7b 35 [2] 50 19 [2] 7e 3b [2] 6a 20 [2] 65 3a [2] 7b 27 [2] 79 26 [2] 62 20 [2] 7e 27 [2] 62 08 }

  condition:
    any of them
}