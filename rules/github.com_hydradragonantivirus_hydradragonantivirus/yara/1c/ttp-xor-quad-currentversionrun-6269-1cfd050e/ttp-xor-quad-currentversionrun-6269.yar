rule TTP_XOR_QUAD_CurrentVersionRun_6269 {
  strings:
    $key_6269 = { 31 06 [2] 15 08 [2] 3e 24 [2] 10 06 [2] 04 1d [2] 0b 07 [2] 15 1a [2] 17 1b [2] 0c 1d [2] 10 1a [2] 0c 35 }

  condition:
    any of them
}