rule TTP_XOR_QUAD_CurrentVersionRun_61dc {
  strings:
    $key_61dc = { 32 b3 [2] 16 bd [2] 3d 91 [2] 13 b3 [2] 07 a8 [2] 08 b2 [2] 16 af [2] 14 ae [2] 0f a8 [2] 13 af [2] 0f 80 }

  condition:
    any of them
}