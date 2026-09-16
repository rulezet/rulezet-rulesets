rule TTP_XOR_QUAD_CurrentVersionRun_991b {
  strings:
    $key_991b = { ca 74 [2] ee 7a [2] c5 56 [2] eb 74 [2] ff 6f [2] f0 75 [2] ee 68 [2] ec 69 [2] f7 6f [2] eb 68 [2] f7 47 }

  condition:
    any of them
}