rule TTP_XOR_QUAD_CurrentVersionRun_4add {
  strings:
    $key_4add = { 19 b2 [2] 3d bc [2] 16 90 [2] 38 b2 [2] 2c a9 [2] 23 b3 [2] 3d ae [2] 3f af [2] 24 a9 [2] 38 ae [2] 24 81 }

  condition:
    any of them
}