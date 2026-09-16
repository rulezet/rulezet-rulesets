rule TTP_XOR_QUAD_CurrentVersionRun_0ac7 {
  strings:
    $key_0ac7 = { 59 a8 [2] 7d a6 [2] 56 8a [2] 78 a8 [2] 6c b3 [2] 63 a9 [2] 7d b4 [2] 7f b5 [2] 64 b3 [2] 78 b4 [2] 64 9b }

  condition:
    any of them
}