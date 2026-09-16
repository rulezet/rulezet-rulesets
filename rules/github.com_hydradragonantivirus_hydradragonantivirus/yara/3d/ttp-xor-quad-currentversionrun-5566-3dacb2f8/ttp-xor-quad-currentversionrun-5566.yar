rule TTP_XOR_QUAD_CurrentVersionRun_5566 {
  strings:
    $key_5566 = { 06 09 [2] 22 07 [2] 09 2b [2] 27 09 [2] 33 12 [2] 3c 08 [2] 22 15 [2] 20 14 [2] 3b 12 [2] 27 15 [2] 3b 3a }

  condition:
    any of them
}