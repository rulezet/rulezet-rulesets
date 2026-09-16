rule TTP_XOR_QUAD_CurrentVersionRun_6419 {
  strings:
    $key_6419 = { 37 76 [2] 13 78 [2] 38 54 [2] 16 76 [2] 02 6d [2] 0d 77 [2] 13 6a [2] 11 6b [2] 0a 6d [2] 16 6a [2] 0a 45 }

  condition:
    any of them
}