rule TTP_XOR_QUAD_CurrentVersionRun_9947 {
  strings:
    $key_9947 = { ca 28 [2] ee 26 [2] c5 0a [2] eb 28 [2] ff 33 [2] f0 29 [2] ee 34 [2] ec 35 [2] f7 33 [2] eb 34 [2] f7 1b }

  condition:
    any of them
}