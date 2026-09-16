rule TTP_XOR_QUAD_CurrentVersionRun_43c2 {
  strings:
    $key_43c2 = { 10 ad [2] 34 a3 [2] 1f 8f [2] 31 ad [2] 25 b6 [2] 2a ac [2] 34 b1 [2] 36 b0 [2] 2d b6 [2] 31 b1 [2] 2d 9e }

  condition:
    any of them
}