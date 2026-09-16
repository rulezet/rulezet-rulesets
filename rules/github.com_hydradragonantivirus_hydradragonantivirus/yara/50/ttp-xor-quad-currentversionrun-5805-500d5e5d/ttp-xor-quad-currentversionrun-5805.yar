rule TTP_XOR_QUAD_CurrentVersionRun_5805 {
  strings:
    $key_5805 = { 0b 6a [2] 2f 64 [2] 04 48 [2] 2a 6a [2] 3e 71 [2] 31 6b [2] 2f 76 [2] 2d 77 [2] 36 71 [2] 2a 76 [2] 36 59 }

  condition:
    any of them
}