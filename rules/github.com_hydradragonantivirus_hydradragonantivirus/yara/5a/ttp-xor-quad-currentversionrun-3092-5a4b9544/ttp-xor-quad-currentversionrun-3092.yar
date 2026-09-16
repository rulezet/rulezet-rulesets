rule TTP_XOR_QUAD_CurrentVersionRun_3092 {
  strings:
    $key_3092 = { 63 fd [2] 47 f3 [2] 6c df [2] 42 fd [2] 56 e6 [2] 59 fc [2] 47 e1 [2] 45 e0 [2] 5e e6 [2] 42 e1 [2] 5e ce }

  condition:
    any of them
}