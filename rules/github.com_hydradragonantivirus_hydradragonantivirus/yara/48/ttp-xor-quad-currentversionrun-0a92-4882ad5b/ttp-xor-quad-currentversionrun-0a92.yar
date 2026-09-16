rule TTP_XOR_QUAD_CurrentVersionRun_0a92 {
  strings:
    $key_0a92 = { 59 fd [2] 7d f3 [2] 56 df [2] 78 fd [2] 6c e6 [2] 63 fc [2] 7d e1 [2] 7f e0 [2] 64 e6 [2] 78 e1 [2] 64 ce }

  condition:
    any of them
}