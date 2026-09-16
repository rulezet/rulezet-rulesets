rule TTP_XOR_QUAD_CurrentVersionRun_6332 {
  strings:
    $key_6332 = { 30 5d [2] 14 53 [2] 3f 7f [2] 11 5d [2] 05 46 [2] 0a 5c [2] 14 41 [2] 16 40 [2] 0d 46 [2] 11 41 [2] 0d 6e }

  condition:
    any of them
}