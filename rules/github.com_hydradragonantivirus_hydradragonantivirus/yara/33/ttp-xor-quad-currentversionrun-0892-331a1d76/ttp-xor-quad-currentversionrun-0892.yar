rule TTP_XOR_QUAD_CurrentVersionRun_0892 {
  strings:
    $key_0892 = { 5b fd [2] 7f f3 [2] 54 df [2] 7a fd [2] 6e e6 [2] 61 fc [2] 7f e1 [2] 7d e0 [2] 66 e6 [2] 7a e1 [2] 66 ce }

  condition:
    any of them
}