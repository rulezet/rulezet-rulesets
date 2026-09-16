rule TTP_XOR_QUAD_CurrentVersionRun_54dc {
  strings:
    $key_54dc = { 07 b3 [2] 23 bd [2] 08 91 [2] 26 b3 [2] 32 a8 [2] 3d b2 [2] 23 af [2] 21 ae [2] 3a a8 [2] 26 af [2] 3a 80 }

  condition:
    any of them
}