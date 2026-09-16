rule TTP_XOR_QUAD_CurrentVersionRun_997e {
  strings:
    $key_997e = { ca 11 [2] ee 1f [2] c5 33 [2] eb 11 [2] ff 0a [2] f0 10 [2] ee 0d [2] ec 0c [2] f7 0a [2] eb 0d [2] f7 22 }

  condition:
    any of them
}