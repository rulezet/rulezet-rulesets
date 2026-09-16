rule TTP_XOR_QUAD_CurrentVersionRun_4429 {
  strings:
    $key_4429 = { 17 46 [2] 33 48 [2] 18 64 [2] 36 46 [2] 22 5d [2] 2d 47 [2] 33 5a [2] 31 5b [2] 2a 5d [2] 36 5a [2] 2a 75 }

  condition:
    any of them
}