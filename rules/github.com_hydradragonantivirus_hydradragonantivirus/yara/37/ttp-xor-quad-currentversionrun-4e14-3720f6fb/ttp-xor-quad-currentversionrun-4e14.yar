rule TTP_XOR_QUAD_CurrentVersionRun_4e14 {
  strings:
    $key_4e14 = { 1d 7b [2] 39 75 [2] 12 59 [2] 3c 7b [2] 28 60 [2] 27 7a [2] 39 67 [2] 3b 66 [2] 20 60 [2] 3c 67 [2] 20 48 }

  condition:
    any of them
}