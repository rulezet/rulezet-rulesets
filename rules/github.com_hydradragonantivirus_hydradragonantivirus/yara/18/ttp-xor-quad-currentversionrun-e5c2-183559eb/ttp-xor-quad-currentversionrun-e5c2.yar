rule TTP_XOR_QUAD_CurrentVersionRun_e5c2 {
  strings:
    $key_e5c2 = { b6 ad [2] 92 a3 [2] b9 8f [2] 97 ad [2] 83 b6 [2] 8c ac [2] 92 b1 [2] 90 b0 [2] 8b b6 [2] 97 b1 [2] 8b 9e }

  condition:
    any of them
}