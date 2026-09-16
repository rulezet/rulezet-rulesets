rule TTP_XOR_QUAD_CurrentVersionRun_6f05 {
  strings:
    $key_6f05 = { 3c 6a [2] 18 64 [2] 33 48 [2] 1d 6a [2] 09 71 [2] 06 6b [2] 18 76 [2] 1a 77 [2] 01 71 [2] 1d 76 [2] 01 59 }

  condition:
    any of them
}