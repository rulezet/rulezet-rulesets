rule TTP_XOR_QUAD_CurrentVersionRun_992b {
  strings:
    $key_992b = { ca 44 [2] ee 4a [2] c5 66 [2] eb 44 [2] ff 5f [2] f0 45 [2] ee 58 [2] ec 59 [2] f7 5f [2] eb 58 [2] f7 77 }

  condition:
    any of them
}