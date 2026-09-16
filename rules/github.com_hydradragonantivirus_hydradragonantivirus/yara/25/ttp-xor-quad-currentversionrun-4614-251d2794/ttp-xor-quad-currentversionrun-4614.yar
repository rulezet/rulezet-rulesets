rule TTP_XOR_QUAD_CurrentVersionRun_4614 {
  strings:
    $key_4614 = { 15 7b [2] 31 75 [2] 1a 59 [2] 34 7b [2] 20 60 [2] 2f 7a [2] 31 67 [2] 33 66 [2] 28 60 [2] 34 67 [2] 28 48 }

  condition:
    any of them
}