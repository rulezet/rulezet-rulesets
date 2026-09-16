rule TTP_XOR_QUAD_CurrentVersionRun_43d9 {
  strings:
    $key_43d9 = { 10 b6 [2] 34 b8 [2] 1f 94 [2] 31 b6 [2] 25 ad [2] 2a b7 [2] 34 aa [2] 36 ab [2] 2d ad [2] 31 aa [2] 2d 85 }

  condition:
    any of them
}