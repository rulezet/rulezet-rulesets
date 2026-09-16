rule TTP_XOR_QUAD_CurrentVersionRun_03c2 {
  strings:
    $key_03c2 = { 50 ad [2] 74 a3 [2] 5f 8f [2] 71 ad [2] 65 b6 [2] 6a ac [2] 74 b1 [2] 76 b0 [2] 6d b6 [2] 71 b1 [2] 6d 9e }

  condition:
    any of them
}