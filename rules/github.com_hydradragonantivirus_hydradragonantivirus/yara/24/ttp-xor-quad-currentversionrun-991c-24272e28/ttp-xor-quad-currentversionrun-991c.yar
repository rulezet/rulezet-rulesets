rule TTP_XOR_QUAD_CurrentVersionRun_991c {
  strings:
    $key_991c = { ca 73 [2] ee 7d [2] c5 51 [2] eb 73 [2] ff 68 [2] f0 72 [2] ee 6f [2] ec 6e [2] f7 68 [2] eb 6f [2] f7 40 }

  condition:
    any of them
}