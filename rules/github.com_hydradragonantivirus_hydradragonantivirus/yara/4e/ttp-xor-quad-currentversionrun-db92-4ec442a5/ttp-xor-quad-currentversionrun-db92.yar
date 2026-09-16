rule TTP_XOR_QUAD_CurrentVersionRun_db92 {
  strings:
    $key_db92 = { 88 fd [2] ac f3 [2] 87 df [2] a9 fd [2] bd e6 [2] b2 fc [2] ac e1 [2] ae e0 [2] b5 e6 [2] a9 e1 [2] b5 ce }

  condition:
    any of them
}