rule TTP_XOR_QUAD_CurrentVersionRun_9ed1 {
  strings:
    $key_9ed1 = { cd be [2] e9 b0 [2] c2 9c [2] ec be [2] f8 a5 [2] f7 bf [2] e9 a2 [2] eb a3 [2] f0 a5 [2] ec a2 [2] f0 8d }

  condition:
    any of them
}