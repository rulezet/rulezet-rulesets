rule TTP_XOR_QUAD_CurrentVersionRun_2663 {
  strings:
    $key_2663 = { 75 0c [2] 51 02 [2] 7a 2e [2] 54 0c [2] 40 17 [2] 4f 0d [2] 51 10 [2] 53 11 [2] 48 17 [2] 54 10 [2] 48 3f }

  condition:
    any of them
}