rule TTP_XOR_QUAD_CurrentVersionRun_3466 {
  strings:
    $key_3466 = { 67 09 [2] 43 07 [2] 68 2b [2] 46 09 [2] 52 12 [2] 5d 08 [2] 43 15 [2] 41 14 [2] 5a 12 [2] 46 15 [2] 5a 3a }

  condition:
    any of them
}