rule TTP_XOR_QUAD_CurrentVersionRun_9b04 {
  strings:
    $key_9b04 = { c8 6b [2] ec 65 [2] c7 49 [2] e9 6b [2] fd 70 [2] f2 6a [2] ec 77 [2] ee 76 [2] f5 70 [2] e9 77 [2] f5 58 }

  condition:
    any of them
}