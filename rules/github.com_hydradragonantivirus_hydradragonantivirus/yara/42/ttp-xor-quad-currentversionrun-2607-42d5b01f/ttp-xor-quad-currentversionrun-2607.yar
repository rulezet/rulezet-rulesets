rule TTP_XOR_QUAD_CurrentVersionRun_2607 {
  strings:
    $key_2607 = { 75 68 [2] 51 66 [2] 7a 4a [2] 54 68 [2] 40 73 [2] 4f 69 [2] 51 74 [2] 53 75 [2] 48 73 [2] 54 74 [2] 48 5b }

  condition:
    any of them
}