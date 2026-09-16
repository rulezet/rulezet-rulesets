rule TTP_XOR_QUAD_CurrentVersionRun_23d9 {
  strings:
    $key_23d9 = { 70 b6 [2] 54 b8 [2] 7f 94 [2] 51 b6 [2] 45 ad [2] 4a b7 [2] 54 aa [2] 56 ab [2] 4d ad [2] 51 aa [2] 4d 85 }

  condition:
    any of them
}