rule TTP_XOR_QUAD_CurrentVersionRun_51dc {
  strings:
    $key_51dc = { 02 b3 [2] 26 bd [2] 0d 91 [2] 23 b3 [2] 37 a8 [2] 38 b2 [2] 26 af [2] 24 ae [2] 3f a8 [2] 23 af [2] 3f 80 }

  condition:
    any of them
}