rule TTP_XOR_QUAD_CurrentVersionRun_996a {
  strings:
    $key_996a = { ca 05 [2] ee 0b [2] c5 27 [2] eb 05 [2] ff 1e [2] f0 04 [2] ee 19 [2] ec 18 [2] f7 1e [2] eb 19 [2] f7 36 }

  condition:
    any of them
}