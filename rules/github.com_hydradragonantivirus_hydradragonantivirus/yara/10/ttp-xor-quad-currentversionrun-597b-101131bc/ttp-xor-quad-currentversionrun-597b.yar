rule TTP_XOR_QUAD_CurrentVersionRun_597b {
  strings:
    $key_597b = { 0a 14 [2] 2e 1a [2] 05 36 [2] 2b 14 [2] 3f 0f [2] 30 15 [2] 2e 08 [2] 2c 09 [2] 37 0f [2] 2b 08 [2] 37 27 }

  condition:
    any of them
}