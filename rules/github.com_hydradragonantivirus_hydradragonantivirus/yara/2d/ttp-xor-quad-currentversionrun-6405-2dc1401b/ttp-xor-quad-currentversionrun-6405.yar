rule TTP_XOR_QUAD_CurrentVersionRun_6405 {
  strings:
    $key_6405 = { 37 6a [2] 13 64 [2] 38 48 [2] 16 6a [2] 02 71 [2] 0d 6b [2] 13 76 [2] 11 77 [2] 0a 71 [2] 16 76 [2] 0a 59 }

  condition:
    any of them
}