rule TTP_XOR_QUAD_CurrentVersionRun_821f {
  strings:
    $key_821f = { d1 70 [2] f5 7e [2] de 52 [2] f0 70 [2] e4 6b [2] eb 71 [2] f5 6c [2] f7 6d [2] ec 6b [2] f0 6c [2] ec 43 }

  condition:
    any of them
}