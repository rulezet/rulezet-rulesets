rule TTP_XOR_QUAD_CurrentVersionRun_0305 {
  strings:
    $key_0305 = { 50 6a [2] 74 64 [2] 5f 48 [2] 71 6a [2] 65 71 [2] 6a 6b [2] 74 76 [2] 76 77 [2] 6d 71 [2] 71 76 [2] 6d 59 }

  condition:
    any of them
}