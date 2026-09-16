rule TTP_XOR_QUAD_CurrentVersionRun_9e92 {
  strings:
    $key_9e92 = { cd fd [2] e9 f3 [2] c2 df [2] ec fd [2] f8 e6 [2] f7 fc [2] e9 e1 [2] eb e0 [2] f0 e6 [2] ec e1 [2] f0 ce }

  condition:
    any of them
}