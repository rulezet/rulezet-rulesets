rule TTP_XOR_QUAD_CurrentVersionRun_05d8 {
  strings:
    $key_05d8 = { 56 b7 [2] 72 b9 [2] 59 95 [2] 77 b7 [2] 63 ac [2] 6c b6 [2] 72 ab [2] 70 aa [2] 6b ac [2] 77 ab [2] 6b 84 }

  condition:
    any of them
}