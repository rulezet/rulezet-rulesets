rule TTP_XOR_QUAD_CurrentVersionRun_826e {
  strings:
    $key_826e = { d1 01 [2] f5 0f [2] de 23 [2] f0 01 [2] e4 1a [2] eb 00 [2] f5 1d [2] f7 1c [2] ec 1a [2] f0 1d [2] ec 32 }

  condition:
    any of them
}