rule TTP_XOR_QUAD_CurrentVersionRun_2b69 {
  strings:
    $key_2b69 = { 78 06 [2] 5c 08 [2] 77 24 [2] 59 06 [2] 4d 1d [2] 42 07 [2] 5c 1a [2] 5e 1b [2] 45 1d [2] 59 1a [2] 45 35 }

  condition:
    any of them
}