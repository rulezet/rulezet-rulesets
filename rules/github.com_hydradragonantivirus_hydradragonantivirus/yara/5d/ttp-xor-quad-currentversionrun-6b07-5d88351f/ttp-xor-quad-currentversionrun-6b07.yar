rule TTP_XOR_QUAD_CurrentVersionRun_6b07 {
  strings:
    $key_6b07 = { 38 68 [2] 1c 66 [2] 37 4a [2] 19 68 [2] 0d 73 [2] 02 69 [2] 1c 74 [2] 1e 75 [2] 05 73 [2] 19 74 [2] 05 5b }

  condition:
    any of them
}