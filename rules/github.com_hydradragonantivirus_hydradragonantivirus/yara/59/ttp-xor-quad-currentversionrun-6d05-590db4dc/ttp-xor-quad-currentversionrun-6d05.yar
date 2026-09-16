rule TTP_XOR_QUAD_CurrentVersionRun_6d05 {
  strings:
    $key_6d05 = { 3e 6a [2] 1a 64 [2] 31 48 [2] 1f 6a [2] 0b 71 [2] 04 6b [2] 1a 76 [2] 18 77 [2] 03 71 [2] 1f 76 [2] 03 59 }

  condition:
    any of them
}