rule TTP_XOR_QUAD_CurrentVersionRun_9be0 {
  strings:
    $key_9be0 = { c8 8f [2] ec 81 [2] c7 ad [2] e9 8f [2] fd 94 [2] f2 8e [2] ec 93 [2] ee 92 [2] f5 94 [2] e9 93 [2] f5 bc }

  condition:
    any of them
}