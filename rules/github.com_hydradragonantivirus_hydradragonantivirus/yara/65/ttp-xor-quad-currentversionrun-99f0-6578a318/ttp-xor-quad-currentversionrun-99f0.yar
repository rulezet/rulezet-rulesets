rule TTP_XOR_QUAD_CurrentVersionRun_99f0 {
  strings:
    $key_99f0 = { ca 9f [2] ee 91 [2] c5 bd [2] eb 9f [2] ff 84 [2] f0 9e [2] ee 83 [2] ec 82 [2] f7 84 [2] eb 83 [2] f7 ac }

  condition:
    any of them
}