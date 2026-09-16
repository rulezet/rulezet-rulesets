rule TTP_XOR_QUAD_CurrentVersionRun_1adc {
  strings:
    $key_1adc = { 49 b3 [2] 6d bd [2] 46 91 [2] 68 b3 [2] 7c a8 [2] 73 b2 [2] 6d af [2] 6f ae [2] 74 a8 [2] 68 af [2] 74 80 }

  condition:
    any of them
}