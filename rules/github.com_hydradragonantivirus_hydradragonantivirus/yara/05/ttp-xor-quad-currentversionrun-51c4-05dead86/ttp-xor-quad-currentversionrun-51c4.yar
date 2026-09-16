rule TTP_XOR_QUAD_CurrentVersionRun_51c4 {
  strings:
    $key_51c4 = { 02 ab [2] 26 a5 [2] 0d 89 [2] 23 ab [2] 37 b0 [2] 38 aa [2] 26 b7 [2] 24 b6 [2] 3f b0 [2] 23 b7 [2] 3f 98 }

  condition:
    any of them
}