rule TTP_XOR_QUAD_CurrentVersionRun_7add {
  strings:
    $key_7add = { 29 b2 [2] 0d bc [2] 26 90 [2] 08 b2 [2] 1c a9 [2] 13 b3 [2] 0d ae [2] 0f af [2] 14 a9 [2] 08 ae [2] 14 81 }

  condition:
    any of them
}