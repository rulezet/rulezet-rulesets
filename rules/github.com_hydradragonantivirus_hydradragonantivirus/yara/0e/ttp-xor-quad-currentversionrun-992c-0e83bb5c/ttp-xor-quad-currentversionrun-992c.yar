rule TTP_XOR_QUAD_CurrentVersionRun_992c {
  strings:
    $key_992c = { ca 43 [2] ee 4d [2] c5 61 [2] eb 43 [2] ff 58 [2] f0 42 [2] ee 5f [2] ec 5e [2] f7 58 [2] eb 5f [2] f7 70 }

  condition:
    any of them
}