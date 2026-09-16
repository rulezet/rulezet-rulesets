rule TTP_XOR_QUAD_CurrentVersionRun_12dc {
  strings:
    $key_12dc = { 41 b3 [2] 65 bd [2] 4e 91 [2] 60 b3 [2] 74 a8 [2] 7b b2 [2] 65 af [2] 67 ae [2] 7c a8 [2] 60 af [2] 7c 80 }

  condition:
    any of them
}