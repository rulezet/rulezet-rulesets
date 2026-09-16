rule TTP_XOR_QUAD_CurrentVersionRun_2adc {
  strings:
    $key_2adc = { 79 b3 [2] 5d bd [2] 76 91 [2] 58 b3 [2] 4c a8 [2] 43 b2 [2] 5d af [2] 5f ae [2] 44 a8 [2] 58 af [2] 44 80 }

  condition:
    any of them
}