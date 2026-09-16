rule TTP_XOR_QUAD_CurrentVersionRun_1969 {
  strings:
    $key_1969 = { 4a 06 [2] 6e 08 [2] 45 24 [2] 6b 06 [2] 7f 1d [2] 70 07 [2] 6e 1a [2] 6c 1b [2] 77 1d [2] 6b 1a [2] 77 35 }

  condition:
    any of them
}