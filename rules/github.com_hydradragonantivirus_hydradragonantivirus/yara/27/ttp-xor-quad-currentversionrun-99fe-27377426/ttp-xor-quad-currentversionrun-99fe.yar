rule TTP_XOR_QUAD_CurrentVersionRun_99fe {
  strings:
    $key_99fe = { ca 91 [2] ee 9f [2] c5 b3 [2] eb 91 [2] ff 8a [2] f0 90 [2] ee 8d [2] ec 8c [2] f7 8a [2] eb 8d [2] f7 a2 }

  condition:
    any of them
}