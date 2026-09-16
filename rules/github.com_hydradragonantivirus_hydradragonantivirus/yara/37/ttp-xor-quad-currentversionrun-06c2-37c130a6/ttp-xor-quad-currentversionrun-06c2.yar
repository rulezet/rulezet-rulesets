rule TTP_XOR_QUAD_CurrentVersionRun_06c2 {
  strings:
    $key_06c2 = { 55 ad [2] 71 a3 [2] 5a 8f [2] 74 ad [2] 60 b6 [2] 6f ac [2] 71 b1 [2] 73 b0 [2] 68 b6 [2] 74 b1 [2] 68 9e }

  condition:
    any of them
}