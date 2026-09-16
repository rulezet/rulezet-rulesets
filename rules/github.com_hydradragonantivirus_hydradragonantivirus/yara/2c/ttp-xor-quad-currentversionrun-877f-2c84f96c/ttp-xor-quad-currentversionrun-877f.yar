rule TTP_XOR_QUAD_CurrentVersionRun_877f {
  strings:
    $key_877f = { d4 10 [2] f0 1e [2] db 32 [2] f5 10 [2] e1 0b [2] ee 11 [2] f0 0c [2] f2 0d [2] e9 0b [2] f5 0c [2] e9 23 }

  condition:
    any of them
}