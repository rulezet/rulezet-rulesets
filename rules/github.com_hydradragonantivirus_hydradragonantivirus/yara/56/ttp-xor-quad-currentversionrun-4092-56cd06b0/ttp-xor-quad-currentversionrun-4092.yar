rule TTP_XOR_QUAD_CurrentVersionRun_4092 {
  strings:
    $key_4092 = { 13 fd [2] 37 f3 [2] 1c df [2] 32 fd [2] 26 e6 [2] 29 fc [2] 37 e1 [2] 35 e0 [2] 2e e6 [2] 32 e1 [2] 2e ce }

  condition:
    any of them
}