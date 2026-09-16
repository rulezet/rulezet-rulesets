rule TTP_XOR_QUAD_CurrentVersionRun_850c {
  strings:
    $key_850c = { d6 63 [2] f2 6d [2] d9 41 [2] f7 63 [2] e3 78 [2] ec 62 [2] f2 7f [2] f0 7e [2] eb 78 [2] f7 7f [2] eb 50 }

  condition:
    any of them
}