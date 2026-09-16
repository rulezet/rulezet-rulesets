rule TTP_XOR_QUAD_CurrentVersionRun_4906 {
  strings:
    $key_4906 = { 1a 69 [2] 3e 67 [2] 15 4b [2] 3b 69 [2] 2f 72 [2] 20 68 [2] 3e 75 [2] 3c 74 [2] 27 72 [2] 3b 75 [2] 27 5a }

  condition:
    any of them
}