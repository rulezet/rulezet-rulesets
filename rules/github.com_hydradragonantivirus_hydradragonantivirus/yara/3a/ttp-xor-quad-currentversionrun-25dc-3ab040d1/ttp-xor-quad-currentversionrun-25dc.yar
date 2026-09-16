rule TTP_XOR_QUAD_CurrentVersionRun_25dc {
  strings:
    $key_25dc = { 76 b3 [2] 52 bd [2] 79 91 [2] 57 b3 [2] 43 a8 [2] 4c b2 [2] 52 af [2] 50 ae [2] 4b a8 [2] 57 af [2] 4b 80 }

  condition:
    any of them
}