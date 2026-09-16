rule TTP_XOR_QUAD_CurrentVersionRun_8210 {
  strings:
    $key_8210 = { d1 7f [2] f5 71 [2] de 5d [2] f0 7f [2] e4 64 [2] eb 7e [2] f5 63 [2] f7 62 [2] ec 64 [2] f0 63 [2] ec 4c }

  condition:
    any of them
}