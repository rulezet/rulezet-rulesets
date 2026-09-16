rule TTP_XOR_QUAD_CurrentVersionRun_99bf {
  strings:
    $key_99bf = { ca d0 [2] ee de [2] c5 f2 [2] eb d0 [2] ff cb [2] f0 d1 [2] ee cc [2] ec cd [2] f7 cb [2] eb cc [2] f7 e3 }

  condition:
    any of them
}