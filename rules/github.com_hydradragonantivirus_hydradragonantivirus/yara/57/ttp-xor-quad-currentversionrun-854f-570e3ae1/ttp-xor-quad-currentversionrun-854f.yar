rule TTP_XOR_QUAD_CurrentVersionRun_854f {
  strings:
    $key_854f = { d6 20 [2] f2 2e [2] d9 02 [2] f7 20 [2] e3 3b [2] ec 21 [2] f2 3c [2] f0 3d [2] eb 3b [2] f7 3c [2] eb 13 }

  condition:
    any of them
}