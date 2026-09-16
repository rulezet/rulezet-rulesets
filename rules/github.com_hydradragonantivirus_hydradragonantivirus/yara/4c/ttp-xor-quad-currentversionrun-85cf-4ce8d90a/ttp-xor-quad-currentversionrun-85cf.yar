rule TTP_XOR_QUAD_CurrentVersionRun_85cf {
  strings:
    $key_85cf = { d6 a0 [2] f2 ae [2] d9 82 [2] f7 a0 [2] e3 bb [2] ec a1 [2] f2 bc [2] f0 bd [2] eb bb [2] f7 bc [2] eb 93 }

  condition:
    any of them
}