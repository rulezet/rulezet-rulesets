rule TTP_XOR_QUAD_CurrentVersionRun_31dc {
  strings:
    $key_31dc = { 62 b3 [2] 46 bd [2] 6d 91 [2] 43 b3 [2] 57 a8 [2] 58 b2 [2] 46 af [2] 44 ae [2] 5f a8 [2] 43 af [2] 5f 80 }

  condition:
    any of them
}