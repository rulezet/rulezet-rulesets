rule TTP_XOR_QUAD_CurrentVersionRun_9960 {
  strings:
    $key_9960 = { ca 0f [2] ee 01 [2] c5 2d [2] eb 0f [2] ff 14 [2] f0 0e [2] ee 13 [2] ec 12 [2] f7 14 [2] eb 13 [2] f7 3c }

  condition:
    any of them
}