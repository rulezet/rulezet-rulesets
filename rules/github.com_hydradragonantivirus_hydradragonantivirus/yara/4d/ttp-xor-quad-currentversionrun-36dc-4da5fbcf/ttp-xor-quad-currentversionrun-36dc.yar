rule TTP_XOR_QUAD_CurrentVersionRun_36dc {
  strings:
    $key_36dc = { 65 b3 [2] 41 bd [2] 6a 91 [2] 44 b3 [2] 50 a8 [2] 5f b2 [2] 41 af [2] 43 ae [2] 58 a8 [2] 44 af [2] 58 80 }

  condition:
    any of them
}