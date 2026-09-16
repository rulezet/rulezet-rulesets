rule TTP_XOR_QUAD_CurrentVersionRun_12d3 {
  strings:
    $key_12d3 = { 41 bc [2] 65 b2 [2] 4e 9e [2] 60 bc [2] 74 a7 [2] 7b bd [2] 65 a0 [2] 67 a1 [2] 7c a7 [2] 60 a0 [2] 7c 8f }

  condition:
    any of them
}