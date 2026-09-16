rule TTP_XOR_QUAD_CurrentVersionRun_996f {
  strings:
    $key_996f = { ca 00 [2] ee 0e [2] c5 22 [2] eb 00 [2] ff 1b [2] f0 01 [2] ee 1c [2] ec 1d [2] f7 1b [2] eb 1c [2] f7 33 }

  condition:
    any of them
}