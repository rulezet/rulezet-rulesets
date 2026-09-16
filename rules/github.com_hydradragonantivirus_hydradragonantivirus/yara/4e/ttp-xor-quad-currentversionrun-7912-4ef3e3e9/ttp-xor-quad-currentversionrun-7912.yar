rule TTP_XOR_QUAD_CurrentVersionRun_7912 {
  strings:
    $key_7912 = { 2a 7d [2] 0e 73 [2] 25 5f [2] 0b 7d [2] 1f 66 [2] 10 7c [2] 0e 61 [2] 0c 60 [2] 17 66 [2] 0b 61 [2] 17 4e }

  condition:
    any of them
}