rule TTP_XOR_QUAD_CurrentVersionRun_60c2 {
  strings:
    $key_60c2 = { 33 ad [2] 17 a3 [2] 3c 8f [2] 12 ad [2] 06 b6 [2] 09 ac [2] 17 b1 [2] 15 b0 [2] 0e b6 [2] 12 b1 [2] 0e 9e }

  condition:
    any of them
}