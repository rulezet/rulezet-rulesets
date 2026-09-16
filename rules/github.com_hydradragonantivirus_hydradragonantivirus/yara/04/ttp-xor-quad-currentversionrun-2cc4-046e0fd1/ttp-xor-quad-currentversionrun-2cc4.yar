rule TTP_XOR_QUAD_CurrentVersionRun_2cc4 {
  strings:
    $key_2cc4 = { 7f ab [2] 5b a5 [2] 70 89 [2] 5e ab [2] 4a b0 [2] 45 aa [2] 5b b7 [2] 59 b6 [2] 42 b0 [2] 5e b7 [2] 42 98 }

  condition:
    any of them
}