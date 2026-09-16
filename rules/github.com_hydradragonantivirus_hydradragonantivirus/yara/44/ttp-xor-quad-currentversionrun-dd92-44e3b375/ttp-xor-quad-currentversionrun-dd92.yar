rule TTP_XOR_QUAD_CurrentVersionRun_dd92 {
  strings:
    $key_dd92 = { 8e fd [2] aa f3 [2] 81 df [2] af fd [2] bb e6 [2] b4 fc [2] aa e1 [2] a8 e0 [2] b3 e6 [2] af e1 [2] b3 ce }

  condition:
    any of them
}