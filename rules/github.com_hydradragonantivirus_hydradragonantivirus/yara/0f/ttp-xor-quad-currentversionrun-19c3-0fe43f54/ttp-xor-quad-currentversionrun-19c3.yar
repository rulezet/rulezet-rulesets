rule TTP_XOR_QUAD_CurrentVersionRun_19c3 {
  strings:
    $key_19c3 = { 4a ac [2] 6e a2 [2] 45 8e [2] 6b ac [2] 7f b7 [2] 70 ad [2] 6e b0 [2] 6c b1 [2] 77 b7 [2] 6b b0 [2] 77 9f }

  condition:
    any of them
}