rule TTP_XOR_QUAD_CurrentVersionRun_9952 {
  strings:
    $key_9952 = { ca 3d [2] ee 33 [2] c5 1f [2] eb 3d [2] ff 26 [2] f0 3c [2] ee 21 [2] ec 20 [2] f7 26 [2] eb 21 [2] f7 0e }

  condition:
    any of them
}