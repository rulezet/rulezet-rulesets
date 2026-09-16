rule TTP_XOR_QUAD_CurrentVersionRun_4c32 {
  strings:
    $key_4c32 = { 1f 5d [2] 3b 53 [2] 10 7f [2] 3e 5d [2] 2a 46 [2] 25 5c [2] 3b 41 [2] 39 40 [2] 22 46 [2] 3e 41 [2] 22 6e }

  condition:
    any of them
}