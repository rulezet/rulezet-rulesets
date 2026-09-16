rule TTP_XOR_QUAD_CurrentVersionRun_0317 {
  strings:
    $key_0317 = { 50 78 [2] 74 76 [2] 5f 5a [2] 71 78 [2] 65 63 [2] 6a 79 [2] 74 64 [2] 76 65 [2] 6d 63 [2] 71 64 [2] 6d 4b }

  condition:
    any of them
}