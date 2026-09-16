rule TTP_XOR_QUAD_CurrentVersionRun_46dc {
  strings:
    $key_46dc = { 15 b3 [2] 31 bd [2] 1a 91 [2] 34 b3 [2] 20 a8 [2] 2f b2 [2] 31 af [2] 33 ae [2] 28 a8 [2] 34 af [2] 28 80 }

  condition:
    any of them
}