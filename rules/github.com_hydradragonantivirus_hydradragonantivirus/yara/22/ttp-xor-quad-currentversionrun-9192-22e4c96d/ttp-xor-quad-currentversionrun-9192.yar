rule TTP_XOR_QUAD_CurrentVersionRun_9192 {
  strings:
    $key_9192 = { c2 fd [2] e6 f3 [2] cd df [2] e3 fd [2] f7 e6 [2] f8 fc [2] e6 e1 [2] e4 e0 [2] ff e6 [2] e3 e1 [2] ff ce }

  condition:
    any of them
}