rule TTP_XOR_QUAD_CurrentVersionRun_99ca {
  strings:
    $key_99ca = { ca a5 [2] ee ab [2] c5 87 [2] eb a5 [2] ff be [2] f0 a4 [2] ee b9 [2] ec b8 [2] f7 be [2] eb b9 [2] f7 96 }

  condition:
    any of them
}