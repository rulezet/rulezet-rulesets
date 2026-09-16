rule TTP_XOR_QUAD_CurrentVersionRun_50d9 {
  strings:
    $key_50d9 = { 03 b6 [2] 27 b8 [2] 0c 94 [2] 22 b6 [2] 36 ad [2] 39 b7 [2] 27 aa [2] 25 ab [2] 3e ad [2] 22 aa [2] 3e 85 }

  condition:
    any of them
}