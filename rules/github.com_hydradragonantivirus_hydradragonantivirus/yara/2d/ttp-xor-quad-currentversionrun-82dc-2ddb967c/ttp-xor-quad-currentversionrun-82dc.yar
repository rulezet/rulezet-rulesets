rule TTP_XOR_QUAD_CurrentVersionRun_82dc {
  strings:
    $key_82dc = { d1 b3 [2] f5 bd [2] de 91 [2] f0 b3 [2] e4 a8 [2] eb b2 [2] f5 af [2] f7 ae [2] ec a8 [2] f0 af [2] ec 80 }

  condition:
    any of them
}