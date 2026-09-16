rule TTP_XOR_QUAD_CurrentVersionRun_02d9 {
  strings:
    $key_02d9 = { 51 b6 [2] 75 b8 [2] 5e 94 [2] 70 b6 [2] 64 ad [2] 6b b7 [2] 75 aa [2] 77 ab [2] 6c ad [2] 70 aa [2] 6c 85 }

  condition:
    any of them
}