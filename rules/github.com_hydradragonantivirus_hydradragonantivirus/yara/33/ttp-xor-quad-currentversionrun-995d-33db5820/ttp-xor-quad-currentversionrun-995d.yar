rule TTP_XOR_QUAD_CurrentVersionRun_995d {
  strings:
    $key_995d = { ca 32 [2] ee 3c [2] c5 10 [2] eb 32 [2] ff 29 [2] f0 33 [2] ee 2e [2] ec 2f [2] f7 29 [2] eb 2e [2] f7 01 }

  condition:
    any of them
}