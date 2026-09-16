rule TTP_XOR_QUAD_CurrentVersionRun_820d {
  strings:
    $key_820d = { d1 62 [2] f5 6c [2] de 40 [2] f0 62 [2] e4 79 [2] eb 63 [2] f5 7e [2] f7 7f [2] ec 79 [2] f0 7e [2] ec 51 }

  condition:
    any of them
}