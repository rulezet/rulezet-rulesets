rule TTP_XOR_QUAD_CurrentVersionRun_07c2 {
  strings:
    $key_07c2 = { 54 ad [2] 70 a3 [2] 5b 8f [2] 75 ad [2] 61 b6 [2] 6e ac [2] 70 b1 [2] 72 b0 [2] 69 b6 [2] 75 b1 [2] 69 9e }

  condition:
    any of them
}