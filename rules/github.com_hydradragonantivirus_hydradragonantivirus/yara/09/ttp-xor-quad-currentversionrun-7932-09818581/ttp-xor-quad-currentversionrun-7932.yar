rule TTP_XOR_QUAD_CurrentVersionRun_7932 {
  strings:
    $key_7932 = { 2a 5d [2] 0e 53 [2] 25 7f [2] 0b 5d [2] 1f 46 [2] 10 5c [2] 0e 41 [2] 0c 40 [2] 17 46 [2] 0b 41 [2] 17 6e }

  condition:
    any of them
}