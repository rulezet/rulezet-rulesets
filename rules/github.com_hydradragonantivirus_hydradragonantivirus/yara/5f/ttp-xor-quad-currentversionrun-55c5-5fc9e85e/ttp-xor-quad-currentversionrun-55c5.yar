rule TTP_XOR_QUAD_CurrentVersionRun_55c5 {
  strings:
    $key_55c5 = { 06 aa [2] 22 a4 [2] 09 88 [2] 27 aa [2] 33 b1 [2] 3c ab [2] 22 b6 [2] 20 b7 [2] 3b b1 [2] 27 b6 [2] 3b 99 }

  condition:
    any of them
}