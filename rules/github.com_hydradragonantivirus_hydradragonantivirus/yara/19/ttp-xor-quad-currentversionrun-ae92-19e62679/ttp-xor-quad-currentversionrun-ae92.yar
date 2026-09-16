rule TTP_XOR_QUAD_CurrentVersionRun_ae92 {
  strings:
    $key_ae92 = { fd fd [2] d9 f3 [2] f2 df [2] dc fd [2] c8 e6 [2] c7 fc [2] d9 e1 [2] db e0 [2] c0 e6 [2] dc e1 [2] c0 ce }

  condition:
    any of them
}