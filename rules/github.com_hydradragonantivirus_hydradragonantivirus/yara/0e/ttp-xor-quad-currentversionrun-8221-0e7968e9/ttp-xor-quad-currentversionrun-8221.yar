rule TTP_XOR_QUAD_CurrentVersionRun_8221 {
  strings:
    $key_8221 = { d1 4e [2] f5 40 [2] de 6c [2] f0 4e [2] e4 55 [2] eb 4f [2] f5 52 [2] f7 53 [2] ec 55 [2] f0 52 [2] ec 7d }

  condition:
    any of them
}