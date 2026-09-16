rule TTP_XOR_QUAD_CurrentVersionRun_4932 {
  strings:
    $key_4932 = { 1a 5d [2] 3e 53 [2] 15 7f [2] 3b 5d [2] 2f 46 [2] 20 5c [2] 3e 41 [2] 3c 40 [2] 27 46 [2] 3b 41 [2] 27 6e }

  condition:
    any of them
}