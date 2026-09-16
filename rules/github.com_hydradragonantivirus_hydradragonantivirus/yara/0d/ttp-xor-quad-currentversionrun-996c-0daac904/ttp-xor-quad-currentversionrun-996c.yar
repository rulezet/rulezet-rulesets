rule TTP_XOR_QUAD_CurrentVersionRun_996c {
  strings:
    $key_996c = { ca 03 [2] ee 0d [2] c5 21 [2] eb 03 [2] ff 18 [2] f0 02 [2] ee 1f [2] ec 1e [2] f7 18 [2] eb 1f [2] f7 30 }

  condition:
    any of them
}