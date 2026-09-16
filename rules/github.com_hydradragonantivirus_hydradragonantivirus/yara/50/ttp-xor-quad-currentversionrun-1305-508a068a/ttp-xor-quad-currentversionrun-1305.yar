rule TTP_XOR_QUAD_CurrentVersionRun_1305 {
  strings:
    $key_1305 = { 40 6a [2] 64 64 [2] 4f 48 [2] 61 6a [2] 75 71 [2] 7a 6b [2] 64 76 [2] 66 77 [2] 7d 71 [2] 61 76 [2] 7d 59 }

  condition:
    any of them
}