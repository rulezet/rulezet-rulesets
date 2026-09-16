rule TTP_XOR_QUAD_CurrentVersionRun_6014 {
  strings:
    $key_6014 = { 33 7b [2] 17 75 [2] 3c 59 [2] 12 7b [2] 06 60 [2] 09 7a [2] 17 67 [2] 15 66 [2] 0e 60 [2] 12 67 [2] 0e 48 }

  condition:
    any of them
}