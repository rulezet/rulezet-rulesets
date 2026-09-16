rule TTP_XOR_QUAD_CurrentVersionRun_8262 {
  strings:
    $key_8262 = { d1 0d [2] f5 03 [2] de 2f [2] f0 0d [2] e4 16 [2] eb 0c [2] f5 11 [2] f7 10 [2] ec 16 [2] f0 11 [2] ec 3e }

  condition:
    any of them
}