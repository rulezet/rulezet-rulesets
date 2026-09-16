rule TTP_XOR_QUAD_CurrentVersionRun_820e {
  strings:
    $key_820e = { d1 61 [2] f5 6f [2] de 43 [2] f0 61 [2] e4 7a [2] eb 60 [2] f5 7d [2] f7 7c [2] ec 7a [2] f0 7d [2] ec 52 }

  condition:
    any of them
}