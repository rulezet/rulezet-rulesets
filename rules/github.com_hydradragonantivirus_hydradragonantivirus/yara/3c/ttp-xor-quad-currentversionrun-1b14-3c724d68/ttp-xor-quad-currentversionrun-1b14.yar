rule TTP_XOR_QUAD_CurrentVersionRun_1b14 {
  strings:
    $key_1b14 = { 48 7b [2] 6c 75 [2] 47 59 [2] 69 7b [2] 7d 60 [2] 72 7a [2] 6c 67 [2] 6e 66 [2] 75 60 [2] 69 67 [2] 75 48 }

  condition:
    any of them
}