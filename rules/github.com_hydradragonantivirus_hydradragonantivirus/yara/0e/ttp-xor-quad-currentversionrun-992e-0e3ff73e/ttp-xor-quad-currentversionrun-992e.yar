rule TTP_XOR_QUAD_CurrentVersionRun_992e {
  strings:
    $key_992e = { ca 41 [2] ee 4f [2] c5 63 [2] eb 41 [2] ff 5a [2] f0 40 [2] ee 5d [2] ec 5c [2] f7 5a [2] eb 5d [2] f7 72 }

  condition:
    any of them
}