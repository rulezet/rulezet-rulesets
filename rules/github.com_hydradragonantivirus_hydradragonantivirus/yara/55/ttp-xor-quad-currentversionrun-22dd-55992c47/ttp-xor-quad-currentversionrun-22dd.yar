rule TTP_XOR_QUAD_CurrentVersionRun_22dd {
  strings:
    $key_22dd = { 71 b2 [2] 55 bc [2] 7e 90 [2] 50 b2 [2] 44 a9 [2] 4b b3 [2] 55 ae [2] 57 af [2] 4c a9 [2] 50 ae [2] 4c 81 }

  condition:
    any of them
}