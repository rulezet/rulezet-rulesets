rule TTP_XOR_QUAD_CurrentVersionRun_6add {
  strings:
    $key_6add = { 39 b2 [2] 1d bc [2] 36 90 [2] 18 b2 [2] 0c a9 [2] 03 b3 [2] 1d ae [2] 1f af [2] 04 a9 [2] 18 ae [2] 04 81 }

  condition:
    any of them
}