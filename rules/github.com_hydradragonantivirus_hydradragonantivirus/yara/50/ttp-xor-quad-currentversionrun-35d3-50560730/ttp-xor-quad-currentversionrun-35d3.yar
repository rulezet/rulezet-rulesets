rule TTP_XOR_QUAD_CurrentVersionRun_35d3 {
  strings:
    $key_35d3 = { 66 bc [2] 42 b2 [2] 69 9e [2] 47 bc [2] 53 a7 [2] 5c bd [2] 42 a0 [2] 40 a1 [2] 5b a7 [2] 47 a0 [2] 5b 8f }

  condition:
    any of them
}