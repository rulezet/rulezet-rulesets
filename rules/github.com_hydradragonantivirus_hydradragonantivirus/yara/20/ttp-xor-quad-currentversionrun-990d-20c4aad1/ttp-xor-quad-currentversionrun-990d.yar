rule TTP_XOR_QUAD_CurrentVersionRun_990d {
  strings:
    $key_990d = { ca 62 [2] ee 6c [2] c5 40 [2] eb 62 [2] ff 79 [2] f0 63 [2] ee 7e [2] ec 7f [2] f7 79 [2] eb 7e [2] f7 51 }

  condition:
    any of them
}