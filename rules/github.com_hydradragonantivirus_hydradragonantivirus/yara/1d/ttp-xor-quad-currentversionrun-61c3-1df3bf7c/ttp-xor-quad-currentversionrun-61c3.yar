rule TTP_XOR_QUAD_CurrentVersionRun_61c3 {
  strings:
    $key_61c3 = { 32 ac [2] 16 a2 [2] 3d 8e [2] 13 ac [2] 07 b7 [2] 08 ad [2] 16 b0 [2] 14 b1 [2] 0f b7 [2] 13 b0 [2] 0f 9f }

  condition:
    any of them
}