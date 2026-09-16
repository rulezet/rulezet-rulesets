rule TTP_XOR_QUAD_CurrentVersionRun_1b07 {
  strings:
    $key_1b07 = { 48 68 [2] 6c 66 [2] 47 4a [2] 69 68 [2] 7d 73 [2] 72 69 [2] 6c 74 [2] 6e 75 [2] 75 73 [2] 69 74 [2] 75 5b }

  condition:
    any of them
}