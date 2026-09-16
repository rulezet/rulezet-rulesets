rule TTP_XOR_QUAD_CurrentVersionRun_63c2 {
  strings:
    $key_63c2 = { 30 ad [2] 14 a3 [2] 3f 8f [2] 11 ad [2] 05 b6 [2] 0a ac [2] 14 b1 [2] 16 b0 [2] 0d b6 [2] 11 b1 [2] 0d 9e }

  condition:
    any of them
}