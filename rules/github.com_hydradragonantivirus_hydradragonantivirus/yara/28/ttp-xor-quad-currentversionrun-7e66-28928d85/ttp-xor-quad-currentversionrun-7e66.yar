rule TTP_XOR_QUAD_CurrentVersionRun_7e66 {
  strings:
    $key_7e66 = { 2d 09 [2] 09 07 [2] 22 2b [2] 0c 09 [2] 18 12 [2] 17 08 [2] 09 15 [2] 0b 14 [2] 10 12 [2] 0c 15 [2] 10 3a }

  condition:
    any of them
}