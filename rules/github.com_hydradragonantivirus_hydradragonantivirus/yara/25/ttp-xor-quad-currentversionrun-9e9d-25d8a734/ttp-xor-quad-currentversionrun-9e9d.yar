rule TTP_XOR_QUAD_CurrentVersionRun_9e9d {
  strings:
    $key_9e9d = { cd f2 [2] e9 fc [2] c2 d0 [2] ec f2 [2] f8 e9 [2] f7 f3 [2] e9 ee [2] eb ef [2] f0 e9 [2] ec ee [2] f0 c1 }

  condition:
    any of them
}