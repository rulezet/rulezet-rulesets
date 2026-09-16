rule TTP_XOR_QUAD_CurrentVersionRun_9bf8 {
  strings:
    $key_9bf8 = { c8 97 [2] ec 99 [2] c7 b5 [2] e9 97 [2] fd 8c [2] f2 96 [2] ec 8b [2] ee 8a [2] f5 8c [2] e9 8b [2] f5 a4 }

  condition:
    any of them
}