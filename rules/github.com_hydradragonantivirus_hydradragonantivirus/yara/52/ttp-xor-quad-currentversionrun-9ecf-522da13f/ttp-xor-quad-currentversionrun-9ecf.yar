rule TTP_XOR_QUAD_CurrentVersionRun_9ecf {
  strings:
    $key_9ecf = { cd a0 [2] e9 ae [2] c2 82 [2] ec a0 [2] f8 bb [2] f7 a1 [2] e9 bc [2] eb bd [2] f0 bb [2] ec bc [2] f0 93 }

  condition:
    any of them
}