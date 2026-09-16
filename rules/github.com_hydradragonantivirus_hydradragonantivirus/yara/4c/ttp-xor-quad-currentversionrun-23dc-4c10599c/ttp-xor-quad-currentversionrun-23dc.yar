rule TTP_XOR_QUAD_CurrentVersionRun_23dc {
  strings:
    $key_23dc = { 70 b3 [2] 54 bd [2] 7f 91 [2] 51 b3 [2] 45 a8 [2] 4a b2 [2] 54 af [2] 56 ae [2] 4d a8 [2] 51 af [2] 4d 80 }

  condition:
    any of them
}