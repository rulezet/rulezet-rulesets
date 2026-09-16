rule TTP_XOR_QUAD_CurrentVersionRun_9bf4 {
  strings:
    $key_9bf4 = { c8 9b [2] ec 95 [2] c7 b9 [2] e9 9b [2] fd 80 [2] f2 9a [2] ec 87 [2] ee 86 [2] f5 80 [2] e9 87 [2] f5 a8 }

  condition:
    any of them
}