rule TTP_XOR_QUAD_CurrentVersionRun_3a44 {
  strings:
    $key_3a44 = { 69 2b [2] 4d 25 [2] 66 09 [2] 48 2b [2] 5c 30 [2] 53 2a [2] 4d 37 [2] 4f 36 [2] 54 30 [2] 48 37 [2] 54 18 }

  condition:
    any of them
}