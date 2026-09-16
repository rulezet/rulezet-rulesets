rule TTP_XOR_QUAD_CurrentVersionRun_1add {
  strings:
    $key_1add = { 49 b2 [2] 6d bc [2] 46 90 [2] 68 b2 [2] 7c a9 [2] 73 b3 [2] 6d ae [2] 6f af [2] 74 a9 [2] 68 ae [2] 74 81 }

  condition:
    any of them
}