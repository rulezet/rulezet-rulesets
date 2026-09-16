rule TTP_XOR_QUAD_CurrentVersionRun_3a47 {
  strings:
    $key_3a47 = { 69 28 [2] 4d 26 [2] 66 0a [2] 48 28 [2] 5c 33 [2] 53 29 [2] 4d 34 [2] 4f 35 [2] 54 33 [2] 48 34 [2] 54 1b }

  condition:
    any of them
}