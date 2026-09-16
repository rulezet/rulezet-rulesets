rule TTP_XOR_QUAD_CurrentVersionRun_26dc {
  strings:
    $key_26dc = { 75 b3 [2] 51 bd [2] 7a 91 [2] 54 b3 [2] 40 a8 [2] 4f b2 [2] 51 af [2] 53 ae [2] 48 a8 [2] 54 af [2] 48 80 }

  condition:
    any of them
}