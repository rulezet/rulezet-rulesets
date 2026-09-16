rule TTP_XOR_QUAD_CurrentVersionRun_6732 {
  strings:
    $key_6732 = { 34 5d [2] 10 53 [2] 3b 7f [2] 15 5d [2] 01 46 [2] 0e 5c [2] 10 41 [2] 12 40 [2] 09 46 [2] 15 41 [2] 09 6e }

  condition:
    any of them
}