rule TTP_XOR_QUAD_CurrentVersionRun_6f7b {
  strings:
    $key_6f7b = { 3c 14 [2] 18 1a [2] 33 36 [2] 1d 14 [2] 09 0f [2] 06 15 [2] 18 08 [2] 1a 09 [2] 01 0f [2] 1d 08 [2] 01 27 }

  condition:
    any of them
}