rule TTP_XOR_QUAD_CurrentVersionRun_44c5 {
  strings:
    $key_44c5 = { 17 aa [2] 33 a4 [2] 18 88 [2] 36 aa [2] 22 b1 [2] 2d ab [2] 33 b6 [2] 31 b7 [2] 2a b1 [2] 36 b6 [2] 2a 99 }

  condition:
    any of them
}