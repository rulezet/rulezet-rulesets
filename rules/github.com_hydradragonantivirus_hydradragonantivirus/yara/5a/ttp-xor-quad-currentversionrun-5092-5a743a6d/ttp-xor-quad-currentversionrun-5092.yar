rule TTP_XOR_QUAD_CurrentVersionRun_5092 {
  strings:
    $key_5092 = { 03 fd [2] 27 f3 [2] 0c df [2] 22 fd [2] 36 e6 [2] 39 fc [2] 27 e1 [2] 25 e0 [2] 3e e6 [2] 22 e1 [2] 3e ce }

  condition:
    any of them
}