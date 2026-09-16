rule TTP_XOR_QUAD_CurrentVersionRun_35dc {
  strings:
    $key_35dc = { 66 b3 [2] 42 bd [2] 69 91 [2] 47 b3 [2] 53 a8 [2] 5c b2 [2] 42 af [2] 40 ae [2] 5b a8 [2] 47 af [2] 5b 80 }

  condition:
    any of them
}