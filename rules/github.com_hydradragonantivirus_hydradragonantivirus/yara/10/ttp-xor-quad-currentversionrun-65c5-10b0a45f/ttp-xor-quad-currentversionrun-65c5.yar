rule TTP_XOR_QUAD_CurrentVersionRun_65c5 {
  strings:
    $key_65c5 = { 36 aa [2] 12 a4 [2] 39 88 [2] 17 aa [2] 03 b1 [2] 0c ab [2] 12 b6 [2] 10 b7 [2] 0b b1 [2] 17 b6 [2] 0b 99 }

  condition:
    any of them
}