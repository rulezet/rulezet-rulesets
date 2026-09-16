rule TTP_XOR_QUAD_CurrentVersionRun_27c5 {
  strings:
    $key_27c5 = { 74 aa [2] 50 a4 [2] 7b 88 [2] 55 aa [2] 41 b1 [2] 4e ab [2] 50 b6 [2] 52 b7 [2] 49 b1 [2] 55 b6 [2] 49 99 }

  condition:
    any of them
}