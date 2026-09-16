rule TTP_XOR_QUAD_CurrentVersionRun_2c68 {
  strings:
    $key_2c68 = { 7f 07 [2] 5b 09 [2] 70 25 [2] 5e 07 [2] 4a 1c [2] 45 06 [2] 5b 1b [2] 59 1a [2] 42 1c [2] 5e 1b [2] 42 34 }

  condition:
    any of them
}