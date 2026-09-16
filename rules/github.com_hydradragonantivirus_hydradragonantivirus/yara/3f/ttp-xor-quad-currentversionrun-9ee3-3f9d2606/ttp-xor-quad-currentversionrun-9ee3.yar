rule TTP_XOR_QUAD_CurrentVersionRun_9ee3 {
  strings:
    $key_9ee3 = { cd 8c [2] e9 82 [2] c2 ae [2] ec 8c [2] f8 97 [2] f7 8d [2] e9 90 [2] eb 91 [2] f0 97 [2] ec 90 [2] f0 bf }

  condition:
    any of them
}