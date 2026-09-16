rule TTP_XOR_QUAD_CurrentVersionRun_3067 {
  strings:
    $key_3067 = { 63 08 [2] 47 06 [2] 6c 2a [2] 42 08 [2] 56 13 [2] 59 09 [2] 47 14 [2] 45 15 [2] 5e 13 [2] 42 14 [2] 5e 3b }

  condition:
    any of them
}