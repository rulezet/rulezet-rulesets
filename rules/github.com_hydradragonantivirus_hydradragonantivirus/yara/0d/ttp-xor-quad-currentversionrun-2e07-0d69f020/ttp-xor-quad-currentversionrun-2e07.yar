rule TTP_XOR_QUAD_CurrentVersionRun_2e07 {
  strings:
    $key_2e07 = { 7d 68 [2] 59 66 [2] 72 4a [2] 5c 68 [2] 48 73 [2] 47 69 [2] 59 74 [2] 5b 75 [2] 40 73 [2] 5c 74 [2] 40 5b }

  condition:
    any of them
}