rule TTP_XOR_QUAD_CurrentVersionRun_e692 {
  strings:
    $key_e692 = { b5 fd [2] 91 f3 [2] ba df [2] 94 fd [2] 80 e6 [2] 8f fc [2] 91 e1 [2] 93 e0 [2] 88 e6 [2] 94 e1 [2] 88 ce }

  condition:
    any of them
}