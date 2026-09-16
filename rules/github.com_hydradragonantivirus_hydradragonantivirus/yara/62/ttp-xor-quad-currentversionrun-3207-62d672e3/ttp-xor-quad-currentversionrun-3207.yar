rule TTP_XOR_QUAD_CurrentVersionRun_3207 {
  strings:
    $key_3207 = { 61 68 [2] 45 66 [2] 6e 4a [2] 40 68 [2] 54 73 [2] 5b 69 [2] 45 74 [2] 47 75 [2] 5c 73 [2] 40 74 [2] 5c 5b }

  condition:
    any of them
}