rule TTP_XOR_QUAD_CurrentVersionRun_6466 {
  strings:
    $key_6466 = { 37 09 [2] 13 07 [2] 38 2b [2] 16 09 [2] 02 12 [2] 0d 08 [2] 13 15 [2] 11 14 [2] 0a 12 [2] 16 15 [2] 0a 3a }

  condition:
    any of them
}