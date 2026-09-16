rule TTP_XOR_QUAD_CurrentVersionRun_9efc {
  strings:
    $key_9efc = { cd 93 [2] e9 9d [2] c2 b1 [2] ec 93 [2] f8 88 [2] f7 92 [2] e9 8f [2] eb 8e [2] f0 88 [2] ec 8f [2] f0 a0 }

  condition:
    any of them
}