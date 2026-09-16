rule TTP_XOR_QUAD_CurrentVersionRun_ce92 {
  strings:
    $key_ce92 = { 9d fd [2] b9 f3 [2] 92 df [2] bc fd [2] a8 e6 [2] a7 fc [2] b9 e1 [2] bb e0 [2] a0 e6 [2] bc e1 [2] a0 ce }

  condition:
    any of them
}