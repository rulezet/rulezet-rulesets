rule TTP_XOR_QUAD_CurrentVersionRun_991d {
  strings:
    $key_991d = { ca 72 [2] ee 7c [2] c5 50 [2] eb 72 [2] ff 69 [2] f0 73 [2] ee 6e [2] ec 6f [2] f7 69 [2] eb 6e [2] f7 41 }

  condition:
    any of them
}