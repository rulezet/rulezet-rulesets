rule TTP_XOR_QUAD_CurrentVersionRun_13c2 {
  strings:
    $key_13c2 = { 40 ad [2] 64 a3 [2] 4f 8f [2] 61 ad [2] 75 b6 [2] 7a ac [2] 64 b1 [2] 66 b0 [2] 7d b6 [2] 61 b1 [2] 7d 9e }

  condition:
    any of them
}