rule TTP_XOR_QUAD_CurrentVersionRun_3569 {
  strings:
    $key_3569 = { 66 06 [2] 42 08 [2] 69 24 [2] 47 06 [2] 53 1d [2] 5c 07 [2] 42 1a [2] 40 1b [2] 5b 1d [2] 47 1a [2] 5b 35 }

  condition:
    any of them
}