rule TTP_XOR_QUAD_CurrentVersionRun_e4dc {
  strings:
    $key_e4dc = { b7 b3 [2] 93 bd [2] b8 91 [2] 96 b3 [2] 82 a8 [2] 8d b2 [2] 93 af [2] 91 ae [2] 8a a8 [2] 96 af [2] 8a 80 }

  condition:
    any of them
}