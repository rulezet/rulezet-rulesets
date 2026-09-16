rule TTP_XOR_QUAD_CurrentVersionRun_647b {
  strings:
    $key_647b = { 37 14 [2] 13 1a [2] 38 36 [2] 16 14 [2] 02 0f [2] 0d 15 [2] 13 08 [2] 11 09 [2] 0a 0f [2] 16 08 [2] 0a 27 }

  condition:
    any of them
}