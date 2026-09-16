rule TTP_XOR_QUAD_CurrentVersionRun_9ed8 {
  strings:
    $key_9ed8 = { cd b7 [2] e9 b9 [2] c2 95 [2] ec b7 [2] f8 ac [2] f7 b6 [2] e9 ab [2] eb aa [2] f0 ac [2] ec ab [2] f0 84 }

  condition:
    any of them
}