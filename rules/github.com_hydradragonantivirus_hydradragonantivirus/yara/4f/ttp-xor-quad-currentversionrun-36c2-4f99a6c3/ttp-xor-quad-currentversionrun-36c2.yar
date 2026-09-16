rule TTP_XOR_QUAD_CurrentVersionRun_36c2 {
  strings:
    $key_36c2 = { 65 ad [2] 41 a3 [2] 6a 8f [2] 44 ad [2] 50 b6 [2] 5f ac [2] 41 b1 [2] 43 b0 [2] 58 b6 [2] 44 b1 [2] 58 9e }

  condition:
    any of them
}