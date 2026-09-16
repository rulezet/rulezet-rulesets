rule TTP_XOR_QUAD_CurrentVersionRun_6d7b {
  strings:
    $key_6d7b = { 3e 14 [2] 1a 1a [2] 31 36 [2] 1f 14 [2] 0b 0f [2] 04 15 [2] 1a 08 [2] 18 09 [2] 03 0f [2] 1f 08 [2] 03 27 }

  condition:
    any of them
}