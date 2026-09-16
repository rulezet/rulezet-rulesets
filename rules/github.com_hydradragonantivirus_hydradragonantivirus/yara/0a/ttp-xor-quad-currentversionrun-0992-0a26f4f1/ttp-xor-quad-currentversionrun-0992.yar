rule TTP_XOR_QUAD_CurrentVersionRun_0992 {
  strings:
    $key_0992 = { 5a fd [2] 7e f3 [2] 55 df [2] 7b fd [2] 6f e6 [2] 60 fc [2] 7e e1 [2] 7c e0 [2] 67 e6 [2] 7b e1 [2] 67 ce }

  condition:
    any of them
}