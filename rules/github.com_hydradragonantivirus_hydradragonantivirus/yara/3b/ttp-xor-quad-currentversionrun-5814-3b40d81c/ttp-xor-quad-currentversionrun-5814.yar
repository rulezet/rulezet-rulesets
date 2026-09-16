rule TTP_XOR_QUAD_CurrentVersionRun_5814 {
  strings:
    $key_5814 = { 0b 7b [2] 2f 75 [2] 04 59 [2] 2a 7b [2] 3e 60 [2] 31 7a [2] 2f 67 [2] 2d 66 [2] 36 60 [2] 2a 67 [2] 36 48 }

  condition:
    any of them
}