rule TTP_XOR_QUAD_CurrentVersionRun_8a92 {
  strings:
    $key_8a92 = { d9 fd [2] fd f3 [2] d6 df [2] f8 fd [2] ec e6 [2] e3 fc [2] fd e1 [2] ff e0 [2] e4 e6 [2] f8 e1 [2] e4 ce }

  condition:
    any of them
}