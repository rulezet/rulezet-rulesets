rule TTP_XOR_QUAD_CurrentVersionRun_34c5 {
  strings:
    $key_34c5 = { 67 aa [2] 43 a4 [2] 68 88 [2] 46 aa [2] 52 b1 [2] 5d ab [2] 43 b6 [2] 41 b7 [2] 5a b1 [2] 46 b6 [2] 5a 99 }

  condition:
    any of them
}