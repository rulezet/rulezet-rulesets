rule TTP_XOR_QUAD_CurrentVersionRun_990f {
  strings:
    $key_990f = { ca 60 [2] ee 6e [2] c5 42 [2] eb 60 [2] ff 7b [2] f0 61 [2] ee 7c [2] ec 7d [2] f7 7b [2] eb 7c [2] f7 53 }

  condition:
    any of them
}