rule TTP_XOR_QUAD_CurrentVersionRun_ccf1 {
  strings:
    $key_ccf1 = { 9f 9e [2] bb 90 [2] 90 bc [2] be 9e [2] aa 85 [2] a5 9f [2] bb 82 [2] b9 83 [2] a2 85 [2] be 82 [2] a2 ad }

  condition:
    any of them
}