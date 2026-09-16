rule TTP_XOR_QUAD_CurrentVersionRun_f2dc {
  strings:
    $key_f2dc = { a1 b3 [2] 85 bd [2] ae 91 [2] 80 b3 [2] 94 a8 [2] 9b b2 [2] 85 af [2] 87 ae [2] 9c a8 [2] 80 af [2] 9c 80 }

  condition:
    any of them
}