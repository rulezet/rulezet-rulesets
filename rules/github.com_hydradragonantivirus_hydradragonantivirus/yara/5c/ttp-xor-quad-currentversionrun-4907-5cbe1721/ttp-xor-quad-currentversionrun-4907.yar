rule TTP_XOR_QUAD_CurrentVersionRun_4907 {
  strings:
    $key_4907 = { 1a 68 [2] 3e 66 [2] 15 4a [2] 3b 68 [2] 2f 73 [2] 20 69 [2] 3e 74 [2] 3c 75 [2] 27 73 [2] 3b 74 [2] 27 5b }

  condition:
    any of them
}