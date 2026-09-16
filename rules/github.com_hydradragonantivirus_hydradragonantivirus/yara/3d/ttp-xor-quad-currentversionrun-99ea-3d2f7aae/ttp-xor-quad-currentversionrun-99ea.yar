rule TTP_XOR_QUAD_CurrentVersionRun_99ea {
  strings:
    $key_99ea = { ca 85 [2] ee 8b [2] c5 a7 [2] eb 85 [2] ff 9e [2] f0 84 [2] ee 99 [2] ec 98 [2] f7 9e [2] eb 99 [2] f7 b6 }

  condition:
    any of them
}