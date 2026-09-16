rule TTP_XOR_QUAD_CurrentVersionRun_8202 {
  strings:
    $key_8202 = { d1 6d [2] f5 63 [2] de 4f [2] f0 6d [2] e4 76 [2] eb 6c [2] f5 71 [2] f7 70 [2] ec 76 [2] f0 71 [2] ec 5e }

  condition:
    any of them
}