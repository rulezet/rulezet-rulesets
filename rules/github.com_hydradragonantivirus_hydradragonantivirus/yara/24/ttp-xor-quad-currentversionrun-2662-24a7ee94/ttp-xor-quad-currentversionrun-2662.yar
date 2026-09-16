rule TTP_XOR_QUAD_CurrentVersionRun_2662 {
  strings:
    $key_2662 = { 75 0d [2] 51 03 [2] 7a 2f [2] 54 0d [2] 40 16 [2] 4f 0c [2] 51 11 [2] 53 10 [2] 48 16 [2] 54 11 [2] 48 3e }

  condition:
    any of them
}