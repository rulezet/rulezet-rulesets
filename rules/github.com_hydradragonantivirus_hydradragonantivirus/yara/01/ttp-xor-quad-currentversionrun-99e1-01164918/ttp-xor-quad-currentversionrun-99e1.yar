rule TTP_XOR_QUAD_CurrentVersionRun_99e1 {
  strings:
    $key_99e1 = { ca 8e [2] ee 80 [2] c5 ac [2] eb 8e [2] ff 95 [2] f0 8f [2] ee 92 [2] ec 93 [2] f7 95 [2] eb 92 [2] f7 bd }

  condition:
    any of them
}