rule TTP_XOR_QUAD_CurrentVersionRun_8892 {
  strings:
    $key_8892 = { db fd [2] ff f3 [2] d4 df [2] fa fd [2] ee e6 [2] e1 fc [2] ff e1 [2] fd e0 [2] e6 e6 [2] fa e1 [2] e6 ce }

  condition:
    any of them
}