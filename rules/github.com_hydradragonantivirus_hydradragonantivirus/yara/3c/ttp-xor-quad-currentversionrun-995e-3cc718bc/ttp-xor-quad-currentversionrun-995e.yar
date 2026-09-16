rule TTP_XOR_QUAD_CurrentVersionRun_995e {
  strings:
    $key_995e = { ca 31 [2] ee 3f [2] c5 13 [2] eb 31 [2] ff 2a [2] f0 30 [2] ee 2d [2] ec 2c [2] f7 2a [2] eb 2d [2] f7 02 }

  condition:
    any of them
}