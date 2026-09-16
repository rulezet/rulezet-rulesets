rule TTP_XOR_QUAD_CurrentVersionRun_f4dc {
  strings:
    $key_f4dc = { a7 b3 [2] 83 bd [2] a8 91 [2] 86 b3 [2] 92 a8 [2] 9d b2 [2] 83 af [2] 81 ae [2] 9a a8 [2] 86 af [2] 9a 80 }

  condition:
    any of them
}