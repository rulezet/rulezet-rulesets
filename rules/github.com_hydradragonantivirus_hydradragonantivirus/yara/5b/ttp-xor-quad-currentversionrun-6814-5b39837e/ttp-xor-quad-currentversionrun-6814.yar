rule TTP_XOR_QUAD_CurrentVersionRun_6814 {
  strings:
    $key_6814 = { 3b 7b [2] 1f 75 [2] 34 59 [2] 1a 7b [2] 0e 60 [2] 01 7a [2] 1f 67 [2] 1d 66 [2] 06 60 [2] 1a 67 [2] 06 48 }

  condition:
    any of them
}