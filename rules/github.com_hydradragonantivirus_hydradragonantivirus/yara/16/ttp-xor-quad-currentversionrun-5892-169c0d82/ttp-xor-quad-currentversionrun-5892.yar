rule TTP_XOR_QUAD_CurrentVersionRun_5892 {
  strings:
    $key_5892 = { 0b fd [2] 2f f3 [2] 04 df [2] 2a fd [2] 3e e6 [2] 31 fc [2] 2f e1 [2] 2d e0 [2] 36 e6 [2] 2a e1 [2] 36 ce }

  condition:
    any of them
}