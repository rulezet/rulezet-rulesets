rule TTP_XOR_QUAD_CurrentVersionRun_3e92 {
  strings:
    $key_3e92 = { 6d fd [2] 49 f3 [2] 62 df [2] 4c fd [2] 58 e6 [2] 57 fc [2] 49 e1 [2] 4b e0 [2] 50 e6 [2] 4c e1 [2] 50 ce }

  condition:
    any of them
}