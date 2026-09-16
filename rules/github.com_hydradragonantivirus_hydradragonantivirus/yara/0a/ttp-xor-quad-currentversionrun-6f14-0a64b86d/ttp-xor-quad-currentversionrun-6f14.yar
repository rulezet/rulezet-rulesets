rule TTP_XOR_QUAD_CurrentVersionRun_6f14 {
  strings:
    $key_6f14 = { 3c 7b [2] 18 75 [2] 33 59 [2] 1d 7b [2] 09 60 [2] 06 7a [2] 18 67 [2] 1a 66 [2] 01 60 [2] 1d 67 [2] 01 48 }

  condition:
    any of them
}