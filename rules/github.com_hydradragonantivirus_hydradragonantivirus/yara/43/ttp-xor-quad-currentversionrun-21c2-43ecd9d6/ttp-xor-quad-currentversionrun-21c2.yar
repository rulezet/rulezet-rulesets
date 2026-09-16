rule TTP_XOR_QUAD_CurrentVersionRun_21c2 {
  strings:
    $key_21c2 = { 72 ad [2] 56 a3 [2] 7d 8f [2] 53 ad [2] 47 b6 [2] 48 ac [2] 56 b1 [2] 54 b0 [2] 4f b6 [2] 53 b1 [2] 4f 9e }

  condition:
    any of them
}