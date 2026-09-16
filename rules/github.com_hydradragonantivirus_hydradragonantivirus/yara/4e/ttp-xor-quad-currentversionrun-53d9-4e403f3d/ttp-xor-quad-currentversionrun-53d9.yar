rule TTP_XOR_QUAD_CurrentVersionRun_53d9 {
  strings:
    $key_53d9 = { 00 b6 [2] 24 b8 [2] 0f 94 [2] 21 b6 [2] 35 ad [2] 3a b7 [2] 24 aa [2] 26 ab [2] 3d ad [2] 21 aa [2] 3d 85 }

  condition:
    any of them
}