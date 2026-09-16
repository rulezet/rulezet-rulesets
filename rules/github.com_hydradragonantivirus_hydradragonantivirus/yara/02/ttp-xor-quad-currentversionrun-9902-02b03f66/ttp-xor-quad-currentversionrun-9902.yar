rule TTP_XOR_QUAD_CurrentVersionRun_9902 {
  strings:
    $key_9902 = { ca 6d [2] ee 63 [2] c5 4f [2] eb 6d [2] ff 76 [2] f0 6c [2] ee 71 [2] ec 70 [2] f7 76 [2] eb 71 [2] f7 5e }

  condition:
    any of them
}