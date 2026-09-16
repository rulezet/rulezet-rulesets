rule TTP_XOR_QUAD_CurrentVersionRun_9933 {
  strings:
    $key_9933 = { ca 5c [2] ee 52 [2] c5 7e [2] eb 5c [2] ff 47 [2] f0 5d [2] ee 40 [2] ec 41 [2] f7 47 [2] eb 40 [2] f7 6f }

  condition:
    any of them
}