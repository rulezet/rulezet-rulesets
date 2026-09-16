rule TTP_XOR_QUAD_CurrentVersionRun_1832 {
  strings:
    $key_1832 = { 4b 5d [2] 6f 53 [2] 44 7f [2] 6a 5d [2] 7e 46 [2] 71 5c [2] 6f 41 [2] 6d 40 [2] 76 46 [2] 6a 41 [2] 76 6e }

  condition:
    any of them
}