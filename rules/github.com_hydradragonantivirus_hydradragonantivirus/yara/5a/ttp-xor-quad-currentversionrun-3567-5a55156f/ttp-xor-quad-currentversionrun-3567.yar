rule TTP_XOR_QUAD_CurrentVersionRun_3567 {
  strings:
    $key_3567 = { 66 08 [2] 42 06 [2] 69 2a [2] 47 08 [2] 53 13 [2] 5c 09 [2] 42 14 [2] 40 15 [2] 5b 13 [2] 47 14 [2] 5b 3b }

  condition:
    any of them
}