rule TTP_XOR_QUAD_CurrentVersionRun_e5c5 {
  strings:
    $key_e5c5 = { b6 aa [2] 92 a4 [2] b9 88 [2] 97 aa [2] 83 b1 [2] 8c ab [2] 92 b6 [2] 90 b7 [2] 8b b1 [2] 97 b6 [2] 8b 99 }

  condition:
    any of them
}