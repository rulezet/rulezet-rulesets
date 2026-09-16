rule TTP_XOR_QUAD_CurrentVersionRun_823f {
  strings:
    $key_823f = { d1 50 [2] f5 5e [2] de 72 [2] f0 50 [2] e4 4b [2] eb 51 [2] f5 4c [2] f7 4d [2] ec 4b [2] f0 4c [2] ec 63 }

  condition:
    any of them
}