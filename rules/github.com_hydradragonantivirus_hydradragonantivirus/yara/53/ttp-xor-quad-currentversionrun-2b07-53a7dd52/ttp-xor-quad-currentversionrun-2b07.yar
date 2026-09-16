rule TTP_XOR_QUAD_CurrentVersionRun_2b07 {
  strings:
    $key_2b07 = { 78 68 [2] 5c 66 [2] 77 4a [2] 59 68 [2] 4d 73 [2] 42 69 [2] 5c 74 [2] 5e 75 [2] 45 73 [2] 59 74 [2] 45 5b }

  condition:
    any of them
}