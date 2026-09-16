rule TTP_XOR_QUAD_CurrentVersionRun_f466 {
  strings:
    $key_f466 = { a7 09 [2] 83 07 [2] a8 2b [2] 86 09 [2] 92 12 [2] 9d 08 [2] 83 15 [2] 81 14 [2] 9a 12 [2] 86 15 [2] 9a 3a }

  condition:
    any of them
}