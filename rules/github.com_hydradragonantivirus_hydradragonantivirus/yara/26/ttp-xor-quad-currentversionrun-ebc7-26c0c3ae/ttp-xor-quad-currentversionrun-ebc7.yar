rule TTP_XOR_QUAD_CurrentVersionRun_ebc7 {
  strings:
    $key_ebc7 = { b8 a8 [2] 9c a6 [2] b7 8a [2] 99 a8 [2] 8d b3 [2] 82 a9 [2] 9c b4 [2] 9e b5 [2] 85 b3 [2] 99 b4 [2] 85 9b }

  condition:
    any of them
}