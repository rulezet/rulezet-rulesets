rule TTP_XOR_QUAD_CurrentVersionRun_d192 {
  strings:
    $key_d192 = { 82 fd [2] a6 f3 [2] 8d df [2] a3 fd [2] b7 e6 [2] b8 fc [2] a6 e1 [2] a4 e0 [2] bf e6 [2] a3 e1 [2] bf ce }

  condition:
    any of them
}