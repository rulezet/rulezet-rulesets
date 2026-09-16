rule TTP_XOR_QUAD_CurrentVersionRun_9e1f {
  strings:
    $key_9e1f = { cd 70 [2] e9 7e [2] c2 52 [2] ec 70 [2] f8 6b [2] f7 71 [2] e9 6c [2] eb 6d [2] f0 6b [2] ec 6c [2] f0 43 }

  condition:
    any of them
}