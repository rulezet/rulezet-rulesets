rule TTP_XOR_QUAD_CurrentVersionRun_06dc {
  strings:
    $key_06dc = { 55 b3 [2] 71 bd [2] 5a 91 [2] 74 b3 [2] 60 a8 [2] 6f b2 [2] 71 af [2] 73 ae [2] 68 a8 [2] 74 af [2] 68 80 }

  condition:
    any of them
}