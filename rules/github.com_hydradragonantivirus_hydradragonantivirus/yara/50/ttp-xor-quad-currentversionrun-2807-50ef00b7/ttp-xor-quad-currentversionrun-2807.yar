rule TTP_XOR_QUAD_CurrentVersionRun_2807 {
  strings:
    $key_2807 = { 7b 68 [2] 5f 66 [2] 74 4a [2] 5a 68 [2] 4e 73 [2] 41 69 [2] 5f 74 [2] 5d 75 [2] 46 73 [2] 5a 74 [2] 46 5b }

  condition:
    any of them
}