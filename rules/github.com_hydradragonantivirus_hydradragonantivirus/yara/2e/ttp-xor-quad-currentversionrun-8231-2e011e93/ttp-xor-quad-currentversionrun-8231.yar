rule TTP_XOR_QUAD_CurrentVersionRun_8231 {
  strings:
    $key_8231 = { d1 5e [2] f5 50 [2] de 7c [2] f0 5e [2] e4 45 [2] eb 5f [2] f5 42 [2] f7 43 [2] ec 45 [2] f0 42 [2] ec 6d }

  condition:
    any of them
}