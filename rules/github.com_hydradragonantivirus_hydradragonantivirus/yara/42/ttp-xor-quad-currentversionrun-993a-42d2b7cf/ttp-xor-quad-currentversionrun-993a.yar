rule TTP_XOR_QUAD_CurrentVersionRun_993a {
  strings:
    $key_993a = { ca 55 [2] ee 5b [2] c5 77 [2] eb 55 [2] ff 4e [2] f0 54 [2] ee 49 [2] ec 48 [2] f7 4e [2] eb 49 [2] f7 66 }

  condition:
    any of them
}