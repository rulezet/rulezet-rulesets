rule TTP_XOR_QUAD_CurrentVersionRun_9392 {
  strings:
    $key_9392 = { c0 fd [2] e4 f3 [2] cf df [2] e1 fd [2] f5 e6 [2] fa fc [2] e4 e1 [2] e6 e0 [2] fd e6 [2] e1 e1 [2] fd ce }

  condition:
    any of them
}