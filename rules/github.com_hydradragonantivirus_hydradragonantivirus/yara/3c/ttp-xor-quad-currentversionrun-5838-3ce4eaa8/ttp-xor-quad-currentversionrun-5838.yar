rule TTP_XOR_QUAD_CurrentVersionRun_5838 {
  strings:
    $key_5838 = { 0b 57 [2] 2f 59 [2] 04 75 [2] 2a 57 [2] 3e 4c [2] 31 56 [2] 2f 4b [2] 2d 4a [2] 36 4c [2] 2a 4b [2] 36 64 }

  condition:
    any of them
}