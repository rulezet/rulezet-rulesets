rule TTP_XOR_QUAD_CurrentVersionRun_6414 {
  strings:
    $key_6414 = { 37 7b [2] 13 75 [2] 38 59 [2] 16 7b [2] 02 60 [2] 0d 7a [2] 13 67 [2] 11 66 [2] 0a 60 [2] 16 67 [2] 0a 48 }

  condition:
    any of them
}