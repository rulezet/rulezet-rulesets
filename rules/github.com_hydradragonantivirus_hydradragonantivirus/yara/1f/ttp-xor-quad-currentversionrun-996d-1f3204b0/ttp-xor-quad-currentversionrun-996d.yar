rule TTP_XOR_QUAD_CurrentVersionRun_996d {
  strings:
    $key_996d = { ca 02 [2] ee 0c [2] c5 20 [2] eb 02 [2] ff 19 [2] f0 03 [2] ee 1e [2] ec 1f [2] f7 19 [2] eb 1e [2] f7 31 }

  condition:
    any of them
}