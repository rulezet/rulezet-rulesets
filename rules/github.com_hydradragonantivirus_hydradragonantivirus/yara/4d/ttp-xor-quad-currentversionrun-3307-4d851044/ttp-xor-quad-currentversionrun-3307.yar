rule TTP_XOR_QUAD_CurrentVersionRun_3307 {
  strings:
    $key_3307 = { 60 68 [2] 44 66 [2] 6f 4a [2] 41 68 [2] 55 73 [2] 5a 69 [2] 44 74 [2] 46 75 [2] 5d 73 [2] 41 74 [2] 5d 5b }

  condition:
    any of them
}