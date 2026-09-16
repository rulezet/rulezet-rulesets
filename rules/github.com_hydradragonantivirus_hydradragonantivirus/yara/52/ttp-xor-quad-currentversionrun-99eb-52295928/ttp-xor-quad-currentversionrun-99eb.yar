rule TTP_XOR_QUAD_CurrentVersionRun_99eb {
  strings:
    $key_99eb = { ca 84 [2] ee 8a [2] c5 a6 [2] eb 84 [2] ff 9f [2] f0 85 [2] ee 98 [2] ec 99 [2] f7 9f [2] eb 98 [2] f7 b7 }

  condition:
    any of them
}