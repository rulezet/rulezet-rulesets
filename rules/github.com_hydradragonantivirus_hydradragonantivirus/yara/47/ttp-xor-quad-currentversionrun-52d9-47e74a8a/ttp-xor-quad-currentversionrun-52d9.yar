rule TTP_XOR_QUAD_CurrentVersionRun_52d9 {
  strings:
    $key_52d9 = { 01 b6 [2] 25 b8 [2] 0e 94 [2] 20 b6 [2] 34 ad [2] 3b b7 [2] 25 aa [2] 27 ab [2] 3c ad [2] 20 aa [2] 3c 85 }

  condition:
    any of them
}