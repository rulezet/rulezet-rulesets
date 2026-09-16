rule TTP_XOR_QUAD_CurrentVersionRun_0b05 {
  strings:
    $key_0b05 = { 58 6a [2] 7c 64 [2] 57 48 [2] 79 6a [2] 6d 71 [2] 62 6b [2] 7c 76 [2] 7e 77 [2] 65 71 [2] 79 76 [2] 65 59 }

  condition:
    any of them
}