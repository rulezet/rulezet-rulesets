rule TTP_XOR_QUAD_CurrentVersionRun_9ed7 {
  strings:
    $key_9ed7 = { cd b8 [2] e9 b6 [2] c2 9a [2] ec b8 [2] f8 a3 [2] f7 b9 [2] e9 a4 [2] eb a5 [2] f0 a3 [2] ec a4 [2] f0 8b }

  condition:
    any of them
}