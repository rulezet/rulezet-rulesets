rule TTP_XOR_QUAD_CurrentVersionRun_64dc {
  strings:
    $key_64dc = { 37 b3 [2] 13 bd [2] 38 91 [2] 16 b3 [2] 02 a8 [2] 0d b2 [2] 13 af [2] 11 ae [2] 0a a8 [2] 16 af [2] 0a 80 }

  condition:
    any of them
}