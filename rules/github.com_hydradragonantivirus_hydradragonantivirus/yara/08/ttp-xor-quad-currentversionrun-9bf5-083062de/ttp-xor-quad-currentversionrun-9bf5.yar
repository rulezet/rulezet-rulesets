rule TTP_XOR_QUAD_CurrentVersionRun_9bf5 {
  strings:
    $key_9bf5 = { c8 9a [2] ec 94 [2] c7 b8 [2] e9 9a [2] fd 81 [2] f2 9b [2] ec 86 [2] ee 87 [2] f5 81 [2] e9 86 [2] f5 a9 }

  condition:
    any of them
}