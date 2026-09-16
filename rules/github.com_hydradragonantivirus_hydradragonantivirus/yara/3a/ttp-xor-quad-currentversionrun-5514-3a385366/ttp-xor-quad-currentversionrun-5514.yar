rule TTP_XOR_QUAD_CurrentVersionRun_5514 {
  strings:
    $key_5514 = { 06 7b [2] 22 75 [2] 09 59 [2] 27 7b [2] 33 60 [2] 3c 7a [2] 22 67 [2] 20 66 [2] 3b 60 [2] 27 67 [2] 3b 48 }

  condition:
    any of them
}