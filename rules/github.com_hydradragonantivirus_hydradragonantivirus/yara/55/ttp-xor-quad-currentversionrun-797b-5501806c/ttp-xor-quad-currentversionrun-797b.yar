rule TTP_XOR_QUAD_CurrentVersionRun_797b {
  strings:
    $key_797b = { 2a 14 [2] 0e 1a [2] 25 36 [2] 0b 14 [2] 1f 0f [2] 10 15 [2] 0e 08 [2] 0c 09 [2] 17 0f [2] 0b 08 [2] 17 27 }

  condition:
    any of them
}