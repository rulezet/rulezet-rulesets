rule TTP_XOR_QUAD_CurrentVersionRun_b092 {
  strings:
    $key_b092 = { e3 fd [2] c7 f3 [2] ec df [2] c2 fd [2] d6 e6 [2] d9 fc [2] c7 e1 [2] c5 e0 [2] de e6 [2] c2 e1 [2] de ce }

  condition:
    any of them
}