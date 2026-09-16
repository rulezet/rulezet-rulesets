rule TTP_XOR_QUAD_CurrentVersionRun_01dc {
  strings:
    $key_01dc = { 52 b3 [2] 76 bd [2] 5d 91 [2] 73 b3 [2] 67 a8 [2] 68 b2 [2] 76 af [2] 74 ae [2] 6f a8 [2] 73 af [2] 6f 80 }

  condition:
    any of them
}