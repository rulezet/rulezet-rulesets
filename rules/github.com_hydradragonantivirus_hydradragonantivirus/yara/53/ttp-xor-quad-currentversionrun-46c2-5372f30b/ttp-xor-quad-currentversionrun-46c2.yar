rule TTP_XOR_QUAD_CurrentVersionRun_46c2 {
  strings:
    $key_46c2 = { 15 ad [2] 31 a3 [2] 1a 8f [2] 34 ad [2] 20 b6 [2] 2f ac [2] 31 b1 [2] 33 b0 [2] 28 b6 [2] 34 b1 [2] 28 9e }

  condition:
    any of them
}