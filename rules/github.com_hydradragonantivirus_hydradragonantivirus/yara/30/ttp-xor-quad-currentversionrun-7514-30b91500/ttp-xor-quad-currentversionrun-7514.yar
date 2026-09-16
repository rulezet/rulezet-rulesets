rule TTP_XOR_QUAD_CurrentVersionRun_7514 {
  strings:
    $key_7514 = { 26 7b [2] 02 75 [2] 29 59 [2] 07 7b [2] 13 60 [2] 1c 7a [2] 02 67 [2] 00 66 [2] 1b 60 [2] 07 67 [2] 1b 48 }

  condition:
    any of them
}