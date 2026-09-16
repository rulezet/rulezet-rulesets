rule TTP_XOR_QUAD_CurrentVersionRun_994f {
  strings:
    $key_994f = { ca 20 [2] ee 2e [2] c5 02 [2] eb 20 [2] ff 3b [2] f0 21 [2] ee 3c [2] ec 3d [2] f7 3b [2] eb 3c [2] f7 13 }

  condition:
    any of them
}