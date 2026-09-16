rule TTP_XOR_QUAD_CurrentVersionRun_61d9 {
  strings:
    $key_61d9 = { 32 b6 [2] 16 b8 [2] 3d 94 [2] 13 b6 [2] 07 ad [2] 08 b7 [2] 16 aa [2] 14 ab [2] 0f ad [2] 13 aa [2] 0f 85 }

  condition:
    any of them
}