rule TTP_XOR_QUAD_CurrentVersionRun_1032 {
  strings:
    $key_1032 = { 43 5d [2] 67 53 [2] 4c 7f [2] 62 5d [2] 76 46 [2] 79 5c [2] 67 41 [2] 65 40 [2] 7e 46 [2] 62 41 [2] 7e 6e }

  condition:
    any of them
}