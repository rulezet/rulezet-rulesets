rule TTP_XOR_QUAD_CurrentVersionRun_2bc2 {
  strings:
    $key_2bc2 = { 78 ad [2] 5c a3 [2] 77 8f [2] 59 ad [2] 4d b6 [2] 42 ac [2] 5c b1 [2] 5e b0 [2] 45 b6 [2] 59 b1 [2] 45 9e }

  condition:
    any of them
}