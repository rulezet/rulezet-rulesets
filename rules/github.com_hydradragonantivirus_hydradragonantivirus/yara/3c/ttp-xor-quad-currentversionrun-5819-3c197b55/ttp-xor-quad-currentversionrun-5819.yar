rule TTP_XOR_QUAD_CurrentVersionRun_5819 {
  strings:
    $key_5819 = { 0b 76 [2] 2f 78 [2] 04 54 [2] 2a 76 [2] 3e 6d [2] 31 77 [2] 2f 6a [2] 2d 6b [2] 36 6d [2] 2a 6a [2] 36 45 }

  condition:
    any of them
}