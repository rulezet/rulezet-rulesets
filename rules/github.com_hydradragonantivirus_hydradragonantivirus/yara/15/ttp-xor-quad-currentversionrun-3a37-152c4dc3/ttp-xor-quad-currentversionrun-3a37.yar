rule TTP_XOR_QUAD_CurrentVersionRun_3a37 {
  strings:
    $key_3a37 = { 69 58 [2] 4d 56 [2] 66 7a [2] 48 58 [2] 5c 43 [2] 53 59 [2] 4d 44 [2] 4f 45 [2] 54 43 [2] 48 44 [2] 54 6b }

  condition:
    any of them
}