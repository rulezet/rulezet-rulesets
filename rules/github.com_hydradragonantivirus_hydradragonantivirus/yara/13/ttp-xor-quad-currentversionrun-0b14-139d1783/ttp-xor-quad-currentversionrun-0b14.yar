rule TTP_XOR_QUAD_CurrentVersionRun_0b14 {
  strings:
    $key_0b14 = { 58 7b [2] 7c 75 [2] 57 59 [2] 79 7b [2] 6d 60 [2] 62 7a [2] 7c 67 [2] 7e 66 [2] 65 60 [2] 79 67 [2] 65 48 }

  condition:
    any of them
}