rule TTP_XOR_QUAD_CurrentVersionRun_f6dc {
  strings:
    $key_f6dc = { a5 b3 [2] 81 bd [2] aa 91 [2] 84 b3 [2] 90 a8 [2] 9f b2 [2] 81 af [2] 83 ae [2] 98 a8 [2] 84 af [2] 98 80 }

  condition:
    any of them
}