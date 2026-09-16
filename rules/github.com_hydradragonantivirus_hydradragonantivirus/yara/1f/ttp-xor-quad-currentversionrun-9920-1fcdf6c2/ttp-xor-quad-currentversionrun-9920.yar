rule TTP_XOR_QUAD_CurrentVersionRun_9920 {
  strings:
    $key_9920 = { ca 4f [2] ee 41 [2] c5 6d [2] eb 4f [2] ff 54 [2] f0 4e [2] ee 53 [2] ec 52 [2] f7 54 [2] eb 53 [2] f7 7c }

  condition:
    any of them
}