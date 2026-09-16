rule TTP_XOR_QUAD_CurrentVersionRun_45dc {
  strings:
    $key_45dc = { 16 b3 [2] 32 bd [2] 19 91 [2] 37 b3 [2] 23 a8 [2] 2c b2 [2] 32 af [2] 30 ae [2] 2b a8 [2] 37 af [2] 2b 80 }

  condition:
    any of them
}