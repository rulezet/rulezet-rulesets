rule TTP_XOR_QUAD_CurrentVersionRun_994a {
  strings:
    $key_994a = { ca 25 [2] ee 2b [2] c5 07 [2] eb 25 [2] ff 3e [2] f0 24 [2] ee 39 [2] ec 38 [2] f7 3e [2] eb 39 [2] f7 16 }

  condition:
    any of them
}