rule TTP_XOR_QUAD_CurrentVersionRun_3b07 {
  strings:
    $key_3b07 = { 68 68 [2] 4c 66 [2] 67 4a [2] 49 68 [2] 5d 73 [2] 52 69 [2] 4c 74 [2] 4e 75 [2] 55 73 [2] 49 74 [2] 55 5b }

  condition:
    any of them
}