rule TTP_XOR_QUAD_CurrentVersionRun_dff1 {
  strings:
    $key_dff1 = { 8c 9e [2] a8 90 [2] 83 bc [2] ad 9e [2] b9 85 [2] b6 9f [2] a8 82 [2] aa 83 [2] b1 85 [2] ad 82 [2] b1 ad }

  condition:
    any of them
}