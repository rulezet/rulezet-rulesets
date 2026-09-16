rule TTP_XOR_QUAD_CurrentVersionRun_76dc {
  strings:
    $key_76dc = { 25 b3 [2] 01 bd [2] 2a 91 [2] 04 b3 [2] 10 a8 [2] 1f b2 [2] 01 af [2] 03 ae [2] 18 a8 [2] 04 af [2] 18 80 }

  condition:
    any of them
}