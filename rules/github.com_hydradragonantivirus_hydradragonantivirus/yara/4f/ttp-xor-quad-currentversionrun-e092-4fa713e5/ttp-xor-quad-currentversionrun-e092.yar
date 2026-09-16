rule TTP_XOR_QUAD_CurrentVersionRun_e092 {
  strings:
    $key_e092 = { b3 fd [2] 97 f3 [2] bc df [2] 92 fd [2] 86 e6 [2] 89 fc [2] 97 e1 [2] 95 e0 [2] 8e e6 [2] 92 e1 [2] 8e ce }

  condition:
    any of them
}