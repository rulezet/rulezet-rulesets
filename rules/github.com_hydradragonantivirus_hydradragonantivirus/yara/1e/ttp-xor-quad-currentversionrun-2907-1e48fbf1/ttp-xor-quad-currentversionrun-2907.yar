rule TTP_XOR_QUAD_CurrentVersionRun_2907 {
  strings:
    $key_2907 = { 7a 68 [2] 5e 66 [2] 75 4a [2] 5b 68 [2] 4f 73 [2] 40 69 [2] 5e 74 [2] 5c 75 [2] 47 73 [2] 5b 74 [2] 47 5b }

  condition:
    any of them
}