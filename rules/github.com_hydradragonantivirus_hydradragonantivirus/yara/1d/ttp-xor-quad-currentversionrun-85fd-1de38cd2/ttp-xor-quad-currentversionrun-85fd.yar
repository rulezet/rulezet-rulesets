rule TTP_XOR_QUAD_CurrentVersionRun_85fd {
  strings:
    $key_85fd = { d6 92 [2] f2 9c [2] d9 b0 [2] f7 92 [2] e3 89 [2] ec 93 [2] f2 8e [2] f0 8f [2] eb 89 [2] f7 8e [2] eb a1 }

  condition:
    any of them
}