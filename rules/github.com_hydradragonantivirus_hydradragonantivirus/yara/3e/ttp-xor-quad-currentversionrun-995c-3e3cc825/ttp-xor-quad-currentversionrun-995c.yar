rule TTP_XOR_QUAD_CurrentVersionRun_995c {
  strings:
    $key_995c = { ca 33 [2] ee 3d [2] c5 11 [2] eb 33 [2] ff 28 [2] f0 32 [2] ee 2f [2] ec 2e [2] f7 28 [2] eb 2f [2] f7 00 }

  condition:
    any of them
}