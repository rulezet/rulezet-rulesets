rule TTP_XOR_QUAD_CurrentVersionRun_aa92 {
  strings:
    $key_aa92 = { f9 fd [2] dd f3 [2] f6 df [2] d8 fd [2] cc e6 [2] c3 fc [2] dd e1 [2] df e0 [2] c4 e6 [2] d8 e1 [2] c4 ce }

  condition:
    any of them
}