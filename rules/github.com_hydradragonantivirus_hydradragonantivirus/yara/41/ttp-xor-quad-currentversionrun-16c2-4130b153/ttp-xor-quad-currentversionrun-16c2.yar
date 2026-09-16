rule TTP_XOR_QUAD_CurrentVersionRun_16c2 {
  strings:
    $key_16c2 = { 45 ad [2] 61 a3 [2] 4a 8f [2] 64 ad [2] 70 b6 [2] 7f ac [2] 61 b1 [2] 63 b0 [2] 78 b6 [2] 64 b1 [2] 78 9e }

  condition:
    any of them
}