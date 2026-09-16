rule TTP_XOR_QUAD_CurrentVersionRun_33d9 {
  strings:
    $key_33d9 = { 60 b6 [2] 44 b8 [2] 6f 94 [2] 41 b6 [2] 55 ad [2] 5a b7 [2] 44 aa [2] 46 ab [2] 5d ad [2] 41 aa [2] 5d 85 }

  condition:
    any of them
}