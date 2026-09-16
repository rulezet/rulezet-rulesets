rule TTP_XOR_QUAD_CurrentVersionRun_61c4 {
  strings:
    $key_61c4 = { 32 ab [2] 16 a5 [2] 3d 89 [2] 13 ab [2] 07 b0 [2] 08 aa [2] 16 b7 [2] 14 b6 [2] 0f b0 [2] 13 b7 [2] 0f 98 }

  condition:
    any of them
}