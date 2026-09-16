rule TTP_XOR_QUAD_CurrentVersionRun_51c5 {
  strings:
    $key_51c5 = { 02 aa [2] 26 a4 [2] 0d 88 [2] 23 aa [2] 37 b1 [2] 38 ab [2] 26 b6 [2] 24 b7 [2] 3f b1 [2] 23 b6 [2] 3f 99 }

  condition:
    any of them
}