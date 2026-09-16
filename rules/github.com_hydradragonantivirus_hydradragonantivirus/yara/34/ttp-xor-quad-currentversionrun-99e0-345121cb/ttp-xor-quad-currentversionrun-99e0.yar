rule TTP_XOR_QUAD_CurrentVersionRun_99e0 {
  strings:
    $key_99e0 = { ca 8f [2] ee 81 [2] c5 ad [2] eb 8f [2] ff 94 [2] f0 8e [2] ee 93 [2] ec 92 [2] f7 94 [2] eb 93 [2] f7 bc }

  condition:
    any of them
}