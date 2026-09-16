rule TTP_XOR_QUAD_CurrentVersionRun_09d9 {
  strings:
    $key_09d9 = { 5a b6 [2] 7e b8 [2] 55 94 [2] 7b b6 [2] 6f ad [2] 60 b7 [2] 7e aa [2] 7c ab [2] 67 ad [2] 7b aa [2] 67 85 }

  condition:
    any of them
}