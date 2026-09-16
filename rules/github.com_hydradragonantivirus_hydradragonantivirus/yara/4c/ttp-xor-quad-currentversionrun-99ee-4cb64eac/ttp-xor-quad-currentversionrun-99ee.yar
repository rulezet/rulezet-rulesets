rule TTP_XOR_QUAD_CurrentVersionRun_99ee {
  strings:
    $key_99ee = { ca 81 [2] ee 8f [2] c5 a3 [2] eb 81 [2] ff 9a [2] f0 80 [2] ee 9d [2] ec 9c [2] f7 9a [2] eb 9d [2] f7 b2 }

  condition:
    any of them
}