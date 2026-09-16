rule TTP_XOR_QUAD_CurrentVersionRun_990a {
  strings:
    $key_990a = { ca 65 [2] ee 6b [2] c5 47 [2] eb 65 [2] ff 7e [2] f0 64 [2] ee 79 [2] ec 78 [2] f7 7e [2] eb 79 [2] f7 56 }

  condition:
    any of them
}