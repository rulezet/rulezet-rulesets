rule TTP_XOR_QUAD_CurrentVersionRun_7e14 {
  strings:
    $key_7e14 = { 2d 7b [2] 09 75 [2] 22 59 [2] 0c 7b [2] 18 60 [2] 17 7a [2] 09 67 [2] 0b 66 [2] 10 60 [2] 0c 67 [2] 10 48 }

  condition:
    any of them
}