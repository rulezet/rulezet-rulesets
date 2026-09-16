rule TTP_XOR_QUAD_CurrentVersionRun_9900 {
  strings:
    $key_9900 = { ca 6f [2] ee 61 [2] c5 4d [2] eb 6f [2] ff 74 [2] f0 6e [2] ee 73 [2] ec 72 [2] f7 74 [2] eb 73 [2] f7 5c }

  condition:
    any of them
}