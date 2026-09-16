rule TTP_XOR_QUAD_CurrentVersionRun_9bce {
  strings:
    $key_9bce = { c8 a1 [2] ec af [2] c7 83 [2] e9 a1 [2] fd ba [2] f2 a0 [2] ec bd [2] ee bc [2] f5 ba [2] e9 bd [2] f5 92 }

  condition:
    any of them
}