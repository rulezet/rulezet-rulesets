rule TTP_XOR_QUAD_CurrentVersionRun_5305 {
  strings:
    $key_5305 = { 00 6a [2] 24 64 [2] 0f 48 [2] 21 6a [2] 35 71 [2] 3a 6b [2] 24 76 [2] 26 77 [2] 3d 71 [2] 21 76 [2] 3d 59 }

  condition:
    any of them
}