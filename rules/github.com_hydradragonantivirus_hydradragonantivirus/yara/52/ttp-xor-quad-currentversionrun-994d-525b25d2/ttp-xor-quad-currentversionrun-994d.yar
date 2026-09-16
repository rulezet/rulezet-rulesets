rule TTP_XOR_QUAD_CurrentVersionRun_994d {
  strings:
    $key_994d = { ca 22 [2] ee 2c [2] c5 00 [2] eb 22 [2] ff 39 [2] f0 23 [2] ee 3e [2] ec 3f [2] f7 39 [2] eb 3e [2] f7 11 }

  condition:
    any of them
}