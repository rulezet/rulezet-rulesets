rule TTP_XOR_QUAD_CurrentVersionRun_0add {
  strings:
    $key_0add = { 59 b2 [2] 7d bc [2] 56 90 [2] 78 b2 [2] 6c a9 [2] 63 b3 [2] 7d ae [2] 7f af [2] 64 a9 [2] 78 ae [2] 64 81 }

  condition:
    any of them
}