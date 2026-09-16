rule TTP_XOR_QUAD_CurrentVersionRun_5519 {
  strings:
    $key_5519 = { 06 76 [2] 22 78 [2] 09 54 [2] 27 76 [2] 33 6d [2] 3c 77 [2] 22 6a [2] 20 6b [2] 3b 6d [2] 27 6a [2] 3b 45 }

  condition:
    any of them
}