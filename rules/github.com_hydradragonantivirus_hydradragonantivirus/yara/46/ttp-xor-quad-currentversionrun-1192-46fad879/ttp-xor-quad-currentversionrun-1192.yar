rule TTP_XOR_QUAD_CurrentVersionRun_1192 {
  strings:
    $key_1192 = { 42 fd [2] 66 f3 [2] 4d df [2] 63 fd [2] 77 e6 [2] 78 fc [2] 66 e1 [2] 64 e0 [2] 7f e6 [2] 63 e1 [2] 7f ce }

  condition:
    any of them
}