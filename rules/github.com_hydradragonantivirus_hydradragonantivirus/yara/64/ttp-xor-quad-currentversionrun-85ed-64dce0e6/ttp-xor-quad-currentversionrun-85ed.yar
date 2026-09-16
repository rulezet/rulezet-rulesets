rule TTP_XOR_QUAD_CurrentVersionRun_85ed {
  strings:
    $key_85ed = { d6 82 [2] f2 8c [2] d9 a0 [2] f7 82 [2] e3 99 [2] ec 83 [2] f2 9e [2] f0 9f [2] eb 99 [2] f7 9e [2] eb b1 }

  condition:
    any of them
}