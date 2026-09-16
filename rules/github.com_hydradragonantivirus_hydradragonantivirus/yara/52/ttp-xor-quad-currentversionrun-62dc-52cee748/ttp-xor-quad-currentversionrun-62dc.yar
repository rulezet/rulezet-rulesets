rule TTP_XOR_QUAD_CurrentVersionRun_62dc {
  strings:
    $key_62dc = { 31 b3 [2] 15 bd [2] 3e 91 [2] 10 b3 [2] 04 a8 [2] 0b b2 [2] 15 af [2] 17 ae [2] 0c a8 [2] 10 af [2] 0c 80 }

  condition:
    any of them
}