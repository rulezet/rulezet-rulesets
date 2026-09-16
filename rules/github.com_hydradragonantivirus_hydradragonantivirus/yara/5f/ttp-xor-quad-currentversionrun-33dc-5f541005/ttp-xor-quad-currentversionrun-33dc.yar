rule TTP_XOR_QUAD_CurrentVersionRun_33dc {
  strings:
    $key_33dc = { 60 b3 [2] 44 bd [2] 6f 91 [2] 41 b3 [2] 55 a8 [2] 5a b2 [2] 44 af [2] 46 ae [2] 5d a8 [2] 41 af [2] 5d 80 }

  condition:
    any of them
}