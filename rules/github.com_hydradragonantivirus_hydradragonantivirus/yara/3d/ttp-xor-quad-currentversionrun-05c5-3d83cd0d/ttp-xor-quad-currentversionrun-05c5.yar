rule TTP_XOR_QUAD_CurrentVersionRun_05c5 {
  strings:
    $key_05c5 = { 56 aa [2] 72 a4 [2] 59 88 [2] 77 aa [2] 63 b1 [2] 6c ab [2] 72 b6 [2] 70 b7 [2] 6b b1 [2] 77 b6 [2] 6b 99 }

  condition:
    any of them
}