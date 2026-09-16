rule TTP_XOR_QUAD_CurrentVersionRun_9bfc {
  strings:
    $key_9bfc = { c8 93 [2] ec 9d [2] c7 b1 [2] e9 93 [2] fd 88 [2] f2 92 [2] ec 8f [2] ee 8e [2] f5 88 [2] e9 8f [2] f5 a0 }

  condition:
    any of them
}