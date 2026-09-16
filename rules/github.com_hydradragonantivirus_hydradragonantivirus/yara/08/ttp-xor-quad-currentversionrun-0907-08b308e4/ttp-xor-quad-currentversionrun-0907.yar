rule TTP_XOR_QUAD_CurrentVersionRun_0907 {
  strings:
    $key_0907 = { 5a 68 [2] 7e 66 [2] 55 4a [2] 7b 68 [2] 6f 73 [2] 60 69 [2] 7e 74 [2] 7c 75 [2] 67 73 [2] 7b 74 [2] 67 5b }

  condition:
    any of them
}