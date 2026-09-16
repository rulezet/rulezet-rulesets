rule TTP_XOR_QUAD_CurrentVersionRun_6032 {
  strings:
    $key_6032 = { 33 5d [2] 17 53 [2] 3c 7f [2] 12 5d [2] 06 46 [2] 09 5c [2] 17 41 [2] 15 40 [2] 0e 46 [2] 12 41 [2] 0e 6e }

  condition:
    any of them
}