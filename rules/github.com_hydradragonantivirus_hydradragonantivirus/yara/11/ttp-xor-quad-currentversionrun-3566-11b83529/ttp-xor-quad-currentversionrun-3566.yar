rule TTP_XOR_QUAD_CurrentVersionRun_3566 {
  strings:
    $key_3566 = { 66 09 [2] 42 07 [2] 69 2b [2] 47 09 [2] 53 12 [2] 5c 08 [2] 42 15 [2] 40 14 [2] 5b 12 [2] 47 15 [2] 5b 3a }

  condition:
    any of them
}