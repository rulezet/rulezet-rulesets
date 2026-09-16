rule TTP_XOR_QUAD_CurrentVersionRun_6892 {
  strings:
    $key_6892 = { 3b fd [2] 1f f3 [2] 34 df [2] 1a fd [2] 0e e6 [2] 01 fc [2] 1f e1 [2] 1d e0 [2] 06 e6 [2] 1a e1 [2] 06 ce }

  condition:
    any of them
}