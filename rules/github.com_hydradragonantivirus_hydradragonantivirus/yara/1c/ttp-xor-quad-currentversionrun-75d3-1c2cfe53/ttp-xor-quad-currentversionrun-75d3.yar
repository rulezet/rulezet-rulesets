rule TTP_XOR_QUAD_CurrentVersionRun_75d3 {
  strings:
    $key_75d3 = { 26 bc [2] 02 b2 [2] 29 9e [2] 07 bc [2] 13 a7 [2] 1c bd [2] 02 a0 [2] 00 a1 [2] 1b a7 [2] 07 a0 [2] 1b 8f }

  condition:
    any of them
}