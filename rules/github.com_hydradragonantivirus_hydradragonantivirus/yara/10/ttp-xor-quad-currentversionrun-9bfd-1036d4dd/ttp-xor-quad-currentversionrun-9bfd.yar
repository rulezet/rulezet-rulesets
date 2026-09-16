rule TTP_XOR_QUAD_CurrentVersionRun_9bfd {
  strings:
    $key_9bfd = { c8 92 [2] ec 9c [2] c7 b0 [2] e9 92 [2] fd 89 [2] f2 93 [2] ec 8e [2] ee 8f [2] f5 89 [2] e9 8e [2] f5 a1 }

  condition:
    any of them
}