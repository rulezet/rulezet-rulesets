rule TTP_XOR_QUAD_CurrentVersionRun_826c {
  strings:
    $key_826c = { d1 03 [2] f5 0d [2] de 21 [2] f0 03 [2] e4 18 [2] eb 02 [2] f5 1f [2] f7 1e [2] ec 18 [2] f0 1f [2] ec 30 }

  condition:
    any of them
}