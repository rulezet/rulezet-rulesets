rule TTP_XOR_QUAD_CurrentVersionRun_7508 {
  strings:
    $key_7508 = { 26 67 [2] 02 69 [2] 29 45 [2] 07 67 [2] 13 7c [2] 1c 66 [2] 02 7b [2] 00 7a [2] 1b 7c [2] 07 7b [2] 1b 54 }

  condition:
    any of them
}