rule TTP_XOR_QUAD_CurrentVersionRun_99f6 {
  strings:
    $key_99f6 = { ca 99 [2] ee 97 [2] c5 bb [2] eb 99 [2] ff 82 [2] f0 98 [2] ee 85 [2] ec 84 [2] f7 82 [2] eb 85 [2] f7 aa }

  condition:
    any of them
}