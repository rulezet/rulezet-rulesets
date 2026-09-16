rule TTP_XOR_QUAD_CurrentVersionRun_5d14 {
  strings:
    $key_5d14 = { 0e 7b [2] 2a 75 [2] 01 59 [2] 2f 7b [2] 3b 60 [2] 34 7a [2] 2a 67 [2] 28 66 [2] 33 60 [2] 2f 67 [2] 33 48 }

  condition:
    any of them
}