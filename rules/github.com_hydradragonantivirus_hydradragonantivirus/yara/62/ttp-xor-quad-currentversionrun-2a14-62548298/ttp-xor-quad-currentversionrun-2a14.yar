rule TTP_XOR_QUAD_CurrentVersionRun_2a14 {
  strings:
    $key_2a14 = { 79 7b [2] 5d 75 [2] 76 59 [2] 58 7b [2] 4c 60 [2] 43 7a [2] 5d 67 [2] 5f 66 [2] 44 60 [2] 58 67 [2] 44 48 }

  condition:
    any of them
}