rule TTP_XOR_QUAD_CurrentVersionRun_1e92 {
  strings:
    $key_1e92 = { 4d fd [2] 69 f3 [2] 42 df [2] 6c fd [2] 78 e6 [2] 77 fc [2] 69 e1 [2] 6b e0 [2] 70 e6 [2] 6c e1 [2] 70 ce }

  condition:
    any of them
}