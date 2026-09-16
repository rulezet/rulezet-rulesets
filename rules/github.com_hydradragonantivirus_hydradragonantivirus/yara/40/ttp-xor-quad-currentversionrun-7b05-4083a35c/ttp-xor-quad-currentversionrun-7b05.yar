rule TTP_XOR_QUAD_CurrentVersionRun_7b05 {
  strings:
    $key_7b05 = { 28 6a [2] 0c 64 [2] 27 48 [2] 09 6a [2] 1d 71 [2] 12 6b [2] 0c 76 [2] 0e 77 [2] 15 71 [2] 09 76 [2] 15 59 }

  condition:
    any of them
}