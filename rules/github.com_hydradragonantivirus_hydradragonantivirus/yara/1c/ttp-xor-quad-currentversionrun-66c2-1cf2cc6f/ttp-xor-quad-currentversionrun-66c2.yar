rule TTP_XOR_QUAD_CurrentVersionRun_66c2 {
  strings:
    $key_66c2 = { 35 ad [2] 11 a3 [2] 3a 8f [2] 14 ad [2] 00 b6 [2] 0f ac [2] 11 b1 [2] 13 b0 [2] 08 b6 [2] 14 b1 [2] 08 9e }

  condition:
    any of them
}