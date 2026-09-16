rule TTP_XOR_QUAD_CurrentVersionRun_7366 {
  strings:
    $key_7366 = { 20 09 [2] 04 07 [2] 2f 2b [2] 01 09 [2] 15 12 [2] 1a 08 [2] 04 15 [2] 06 14 [2] 1d 12 [2] 01 15 [2] 1d 3a }

  condition:
    any of them
}