rule TTP_XOR_QUAD_CurrentVersionRun_73dc {
  strings:
    $key_73dc = { 20 b3 [2] 04 bd [2] 2f 91 [2] 01 b3 [2] 15 a8 [2] 1a b2 [2] 04 af [2] 06 ae [2] 1d a8 [2] 01 af [2] 1d 80 }

  condition:
    any of them
}