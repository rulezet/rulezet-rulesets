rule TTP_XOR_QUAD_CurrentVersionRun_996b {
  strings:
    $key_996b = { ca 04 [2] ee 0a [2] c5 26 [2] eb 04 [2] ff 1f [2] f0 05 [2] ee 18 [2] ec 19 [2] f7 1f [2] eb 18 [2] f7 37 }

  condition:
    any of them
}