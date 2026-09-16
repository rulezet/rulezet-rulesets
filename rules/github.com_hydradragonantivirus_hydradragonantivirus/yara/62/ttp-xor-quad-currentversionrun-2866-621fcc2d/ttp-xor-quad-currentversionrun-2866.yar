rule TTP_XOR_QUAD_CurrentVersionRun_2866 {
  strings:
    $key_2866 = { 7b 09 [2] 5f 07 [2] 74 2b [2] 5a 09 [2] 4e 12 [2] 41 08 [2] 5f 15 [2] 5d 14 [2] 46 12 [2] 5a 15 [2] 46 3a }

  condition:
    any of them
}