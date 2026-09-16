rule TTP_XOR_QUAD_CurrentVersionRun_9eff {
  strings:
    $key_9eff = { cd 90 [2] e9 9e [2] c2 b2 [2] ec 90 [2] f8 8b [2] f7 91 [2] e9 8c [2] eb 8d [2] f0 8b [2] ec 8c [2] f0 a3 }

  condition:
    any of them
}