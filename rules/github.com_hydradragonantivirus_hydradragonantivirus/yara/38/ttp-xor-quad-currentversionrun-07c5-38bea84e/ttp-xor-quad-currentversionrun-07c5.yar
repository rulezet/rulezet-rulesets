rule TTP_XOR_QUAD_CurrentVersionRun_07c5 {
  strings:
    $key_07c5 = { 54 aa [2] 70 a4 [2] 5b 88 [2] 75 aa [2] 61 b1 [2] 6e ab [2] 70 b6 [2] 72 b7 [2] 69 b1 [2] 75 b6 [2] 69 99 }

  condition:
    any of them
}