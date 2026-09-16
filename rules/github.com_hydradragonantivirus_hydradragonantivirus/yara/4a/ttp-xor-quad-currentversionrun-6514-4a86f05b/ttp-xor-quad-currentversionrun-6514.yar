rule TTP_XOR_QUAD_CurrentVersionRun_6514 {
  strings:
    $key_6514 = { 36 7b [2] 12 75 [2] 39 59 [2] 17 7b [2] 03 60 [2] 0c 7a [2] 12 67 [2] 10 66 [2] 0b 60 [2] 17 67 [2] 0b 48 }

  condition:
    any of them
}