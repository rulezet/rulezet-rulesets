rule TTP_XOR_QUAD_CurrentVersionRun_6792 {
  strings:
    $key_6792 = { 34 fd [2] 10 f3 [2] 3b df [2] 15 fd [2] 01 e6 [2] 0e fc [2] 10 e1 [2] 12 e0 [2] 09 e6 [2] 15 e1 [2] 09 ce }

  condition:
    any of them
}