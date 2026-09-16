rule TTP_XOR_QUAD_CurrentVersionRun_2107 {
  strings:
    $key_2107 = { 72 68 [2] 56 66 [2] 7d 4a [2] 53 68 [2] 47 73 [2] 48 69 [2] 56 74 [2] 54 75 [2] 4f 73 [2] 53 74 [2] 4f 5b }

  condition:
    any of them
}