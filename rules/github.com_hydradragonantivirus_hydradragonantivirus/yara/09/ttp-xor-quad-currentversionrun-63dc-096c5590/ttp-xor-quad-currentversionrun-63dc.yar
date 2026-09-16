rule TTP_XOR_QUAD_CurrentVersionRun_63dc {
  strings:
    $key_63dc = { 30 b3 [2] 14 bd [2] 3f 91 [2] 11 b3 [2] 05 a8 [2] 0a b2 [2] 14 af [2] 16 ae [2] 0d a8 [2] 11 af [2] 0d 80 }

  condition:
    any of them
}