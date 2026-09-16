rule TTP_XOR_QUAD_CurrentVersionRun_55d3 {
  strings:
    $key_55d3 = { 06 bc [2] 22 b2 [2] 09 9e [2] 27 bc [2] 33 a7 [2] 3c bd [2] 22 a0 [2] 20 a1 [2] 3b a7 [2] 27 a0 [2] 3b 8f }

  condition:
    any of them
}