rule TTP_XOR_QUAD_CurrentVersionRun_05d3 {
  strings:
    $key_05d3 = { 56 bc [2] 72 b2 [2] 59 9e [2] 77 bc [2] 63 a7 [2] 6c bd [2] 72 a0 [2] 70 a1 [2] 6b a7 [2] 77 a0 [2] 6b 8f }

  condition:
    any of them
}