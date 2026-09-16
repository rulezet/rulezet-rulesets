rule TTP_XOR_QUAD_CurrentVersionRun_f0dc {
  strings:
    $key_f0dc = { a3 b3 [2] 87 bd [2] ac 91 [2] 82 b3 [2] 96 a8 [2] 99 b2 [2] 87 af [2] 85 ae [2] 9e a8 [2] 82 af [2] 9e 80 }

  condition:
    any of them
}