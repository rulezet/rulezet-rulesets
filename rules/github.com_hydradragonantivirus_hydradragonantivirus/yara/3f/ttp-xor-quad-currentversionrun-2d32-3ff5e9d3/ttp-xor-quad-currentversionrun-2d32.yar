rule TTP_XOR_QUAD_CurrentVersionRun_2d32 {
  strings:
    $key_2d32 = { 7e 5d [2] 5a 53 [2] 71 7f [2] 5f 5d [2] 4b 46 [2] 44 5c [2] 5a 41 [2] 58 40 [2] 43 46 [2] 5f 41 [2] 43 6e }

  condition:
    any of them
}