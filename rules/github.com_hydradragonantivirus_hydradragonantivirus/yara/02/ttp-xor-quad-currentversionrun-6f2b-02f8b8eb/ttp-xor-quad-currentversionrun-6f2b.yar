rule TTP_XOR_QUAD_CurrentVersionRun_6f2b {
  strings:
    $key_6f2b = { 3c 44 [2] 18 4a [2] 33 66 [2] 1d 44 [2] 09 5f [2] 06 45 [2] 18 58 [2] 1a 59 [2] 01 5f [2] 1d 58 [2] 01 77 }

  condition:
    any of them
}