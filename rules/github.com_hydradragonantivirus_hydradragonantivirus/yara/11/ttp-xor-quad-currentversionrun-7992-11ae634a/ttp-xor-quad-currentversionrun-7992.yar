rule TTP_XOR_QUAD_CurrentVersionRun_7992 {
  strings:
    $key_7992 = { 2a fd [2] 0e f3 [2] 25 df [2] 0b fd [2] 1f e6 [2] 10 fc [2] 0e e1 [2] 0c e0 [2] 17 e6 [2] 0b e1 [2] 17 ce }

  condition:
    any of them
}