rule TTP_XOR_QUAD_CurrentVersionRun_3ac7 {
  strings:
    $key_3ac7 = { 69 a8 [2] 4d a6 [2] 66 8a [2] 48 a8 [2] 5c b3 [2] 53 a9 [2] 4d b4 [2] 4f b5 [2] 54 b3 [2] 48 b4 [2] 54 9b }

  condition:
    any of them
}