rule TTP_XOR_QUAD_CurrentVersionRun_99ed {
  strings:
    $key_99ed = { ca 82 [2] ee 8c [2] c5 a0 [2] eb 82 [2] ff 99 [2] f0 83 [2] ee 9e [2] ec 9f [2] f7 99 [2] eb 9e [2] f7 b1 }

  condition:
    any of them
}