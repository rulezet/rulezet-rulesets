rule TTP_XOR_QUAD_CurrentVersionRun_997d {
  strings:
    $key_997d = { ca 12 [2] ee 1c [2] c5 30 [2] eb 12 [2] ff 09 [2] f0 13 [2] ee 0e [2] ec 0f [2] f7 09 [2] eb 0e [2] f7 21 }

  condition:
    any of them
}