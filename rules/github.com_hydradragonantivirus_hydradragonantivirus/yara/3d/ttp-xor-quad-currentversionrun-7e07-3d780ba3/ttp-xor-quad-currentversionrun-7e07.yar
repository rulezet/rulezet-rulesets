rule TTP_XOR_QUAD_CurrentVersionRun_7e07 {
  strings:
    $key_7e07 = { 2d 68 [2] 09 66 [2] 22 4a [2] 0c 68 [2] 18 73 [2] 17 69 [2] 09 74 [2] 0b 75 [2] 10 73 [2] 0c 74 [2] 10 5b }

  condition:
    any of them
}