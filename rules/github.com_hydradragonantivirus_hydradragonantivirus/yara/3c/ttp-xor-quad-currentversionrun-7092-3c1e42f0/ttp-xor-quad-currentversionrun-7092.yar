rule TTP_XOR_QUAD_CurrentVersionRun_7092 {
  strings:
    $key_7092 = { 23 fd [2] 07 f3 [2] 2c df [2] 02 fd [2] 16 e6 [2] 19 fc [2] 07 e1 [2] 05 e0 [2] 1e e6 [2] 02 e1 [2] 1e ce }

  condition:
    any of them
}