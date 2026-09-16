rule TTP_XOR_QUAD_CurrentVersionRun_99f7 {
  strings:
    $key_99f7 = { ca 98 [2] ee 96 [2] c5 ba [2] eb 98 [2] ff 83 [2] f0 99 [2] ee 84 [2] ec 85 [2] f7 83 [2] eb 84 [2] f7 ab }

  condition:
    any of them
}