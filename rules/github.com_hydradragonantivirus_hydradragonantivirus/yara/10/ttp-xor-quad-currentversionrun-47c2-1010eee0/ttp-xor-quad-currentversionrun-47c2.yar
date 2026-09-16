rule TTP_XOR_QUAD_CurrentVersionRun_47c2 {
  strings:
    $key_47c2 = { 14 ad [2] 30 a3 [2] 1b 8f [2] 35 ad [2] 21 b6 [2] 2e ac [2] 30 b1 [2] 32 b0 [2] 29 b6 [2] 35 b1 [2] 29 9e }

  condition:
    any of them
}